// Demo driver: a scripted timeline a viewer can watch move from CLEAN to FLAGGED on the
// operator console.
//
// Attach to any GameObject in an otherwise empty scene and press Play while the demo arbiter
// from tools/unity-demo.ts is running. The three phases exist to make the doctrine falsifiable
// in front of an audience:
//
//   CLEAN        allowlist hits only          -> must never leave CLEAN
//   BEHAVIOURAL  a server-side signal alone   -> may reach PENDING, must never convict
//   STRUCTURAL   a kernel-only proof          -> must convict, and must contain capability
//
// A demo that only showed the cheat being caught would prove the easy half.

using System;
using System.Collections;
using System.Collections.Generic;
using UnityEngine;

namespace Ares.Demo
{
    public sealed class AresDemoAgent : MonoBehaviour
    {
        [Header("Arbiter")]
        [Tooltip("The demo arbiter. tools/unity-demo.ts listens on this port by default.")]
        public string baseUrl = "http://127.0.0.1:8799";

        [Header("Demo")]
        [Tooltip("Names the subject. It becomes a 32-hex digest before it leaves the client.")]
        public string subjectName = "unity-demo-player";

        [Tooltip("Samples per second, per phase.")]
        [Range(1f, 20f)]
        public float perSecond = 4f;

        [Tooltip("Play the timeline on Start.")]
        public bool autoRun = true;

        private readonly List<AresAgent> _agents = new List<AresAgent>();
        private string _subject;
        private bool _running;

        private struct Phase
        {
            public string Label;
            public string Role;
            public string Code;
            public float Seconds;

            public Phase(string label, string role, string code, float seconds)
            {
                Label = label;
                Role = role;
                Code = code;
                Seconds = seconds;
            }
        }

        private static readonly Phase[] Timeline =
        {
            new Phase("CLEAN        allowlist hit", "UMON", "XD", 5f),
            new Phase("BEHAVIOURAL  server-side signal alone", "SRV", "X8", 6f),
            new Phase("STRUCTURAL   foreign write handle", "KMOD", "X2", 10f),
        };

        private void Awake()
        {
            _subject = AresWire.Subject(subjectName);
            // Counters are fixed by the demo arbiter's enrolment order (tools/unity-demo.ts:
            // an empty registry, then KMOD, UMON, SRV), which is what lets the client derive
            // the same identities the arbiter minted without any credential being transferred.
            _agents.Add(new AresAgent("KMOD", 1, AresRing.Kmod));
            _agents.Add(new AresAgent("UMON", 2, AresRing.Umon));
            _agents.Add(new AresAgent("SRV", 3, AresRing.Srv));
        }

        private void Start()
        {
            if (autoRun) StartCoroutine(RunTimeline());
        }

        public IEnumerator RunTimeline()
        {
            if (_running) yield break;
            _running = true;
            Debug.Log("[ares] subject digest " + _subject + " (a digest, never an account id)");
            foreach (Phase phase in Timeline)
            {
                AresAgent agent = Find(phase.Role);
                if (agent == null) continue;
                Debug.Log("[ares] phase " + phase.Label + " as " + phase.Role + " code " + phase.Code);
                float interval = Mathf.Max(0.05f, 1f / perSecond);
                for (float elapsed = 0f; elapsed < phase.Seconds; elapsed += interval)
                {
                    // Await each send so requests from this principal cannot arrive out of order.
                    yield return StartCoroutine(SendOne(agent, phase.Code, 1L));
                    yield return new WaitForSeconds(interval);
                }
            }
            Debug.Log("[ares] timeline complete — the console should read FLAGGED for this subject");
            _running = false;
        }

        /// <summary>
        /// Demonstrates the provenance check: a kernel-only proof declared on the user-mode ring.
        ///
        /// The arbiter answers 403 and counts a spoofed ring claim; nothing is adjudicated. Call
        /// this from a button or from your own code — it is the cheapest way to show that a
        /// compromised client can lie about its ring and the lie is refused rather than scored.
        /// </summary>
        public void SendForgedRingClaim()
        {
            AresAgent kmod = Find("KMOD");
            if (kmod == null) return;
            AresEvent forged = kmod.Next(_subject, "X2", 1L, NowMs());
            forged.r = (int)AresRing.Umon; // the lie under test
            List<AresEvent> batch = new List<AresEvent>();
            batch.Add(forged);
            StartCoroutine(SendBatch(kmod, batch));
        }

        /// <summary>The subject digest this client reports under, for cross-checking the console.</summary>
        public string SubjectDigest
        {
            get { return _subject; }
        }

        private IEnumerator SendOne(AresAgent agent, string code, long measurement)
        {
            List<AresEvent> batch = new List<AresEvent>();
            batch.Add(agent.Next(_subject, code, measurement, NowMs()));
            yield return StartCoroutine(SendBatch(agent, batch));
        }

        private IEnumerator SendBatch(AresAgent agent, List<AresEvent> batch)
        {
            AresIngestClient client = new AresIngestClient(baseUrl, agent);
            yield return StartCoroutine(client.Send(batch, delegate (AresIngestResult result)
            {
                string code = batch[0].c;
                if (result.Ok)
                {
                    Debug.Log("[ares] " + agent.Role + " " + code + " accepted (202)");
                }
                else if (result.Unauthenticated)
                {
                    Debug.LogError("[ares] " + agent.Role + " " + code + " refused 401 — the agent id or key does not match the arbiter's enrolment. Is the demo arbiter the one on port " + baseUrl + "?");
                }
                else
                {
                    Debug.LogWarning("[ares] " + agent.Role + " " + code + " refused " + result.Status + " " + (result.Error ?? result.Body));
                }
            }));
        }

        private AresAgent Find(string role)
        {
            for (int i = 0; i < _agents.Count; i++)
            {
                if (_agents[i].Role == role) return _agents[i];
            }
            return null;
        }

        /// <summary>
        /// Milliseconds since the Unix epoch, UTC.
        ///
        /// The arbiter bounds the sender clock against its own and never trusts it for ordering,
        /// so this only has to be roughly right — the demo runs on one host, where it is exact.
        /// </summary>
        private static long NowMs()
        {
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return (long)(DateTime.UtcNow - epoch).TotalMilliseconds;
        }
    }
}
