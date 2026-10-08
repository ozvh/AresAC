// Unity transport for the demo agent.
//
// The only file in this folder that references UnityEngine: signing, canonicalisation and
// framing all live in ZeusWire.cs so the bytes can be reasoned about, and diffed against the
// arbiter, without an editor.
//
// One batch, one principal. The arbiter refuses a batch that spans two agents, because a single
// MAC cannot honestly cover two keys — grouping by ring is not a style choice here, it is the
// rule the ingest path enforces.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using UnityEngine;
using UnityEngine.Networking;

namespace Zeus.Demo
{
    /// <summary>Outcome of one ingest request, as the demo logs it.</summary>
    public sealed class ZeusIngestResult
    {
        /// <summary>True only on 202, the one status the ingest path accepts a batch with.</summary>
        public bool Ok;
        public long Status;
        public string Body;
        /// <summary>Transport failure text, or null when the arbiter answered.</summary>
        public string Error;

        public bool Unauthenticated { get { return Status == 401; } }
        public bool Rejected { get { return Status == 400 || Status == 403 || Status == 409 || Status == 413 || Status == 415 || Status == 429; } }
    }

    public sealed class ZeusIngestClient
    {
        private readonly string _baseUrl;
        private readonly ZeusAgent _agent;

        public ZeusIngestClient(string baseUrl, ZeusAgent agent)
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _agent = agent;
        }

        public string Endpoint { get { return _baseUrl + "/v1/ingest"; } }
        public ZeusAgent Agent { get { return _agent; } }

        /// <summary>
        /// Sign and post one batch. `onDone` runs whatever the outcome, including a transport
        /// failure: a demo that silently swallows a refused batch teaches the wrong thing.
        /// </summary>
        public IEnumerator Send(List<ZeusEvent> batch, Action<ZeusIngestResult> onDone)
        {
            string canonical = ZeusWire.CanonicalBatch(batch);
            string signature = ZeusWire.Sign(_agent.Key, canonical);
            byte[] payload = Encoding.UTF8.GetBytes(ZeusWire.Body(batch));

            using (UnityWebRequest request = new UnityWebRequest(Endpoint, "POST"))
            {
                request.uploadHandler = new UploadHandlerRaw(payload);
                request.downloadHandler = new DownloadHandlerBuffer();
                request.SetRequestHeader("Content-Type", "application/json");
                request.SetRequestHeader("x-zeus-sig", signature);
                request.timeout = 5;

                yield return request.SendWebRequest();

                ZeusIngestResult result = new ZeusIngestResult();
                // responseCode rather than the isNetworkError/isHttpError shortcuts: those were
                // deprecated in Unity 2022 and the replacements do not exist in older editors.
                // A status of 0 means the request never reached the arbiter at all.
                result.Status = request.responseCode;
                result.Body = request.downloadHandler == null ? string.Empty : request.downloadHandler.text;
                result.Ok = request.responseCode == 202;
                result.Error = result.Status == 0 ? (request.error ?? "no response") : null;
                if (onDone != null) onDone(result);
            }
        }
    }
}
