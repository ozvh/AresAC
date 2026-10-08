// ZEUS wire protocol core — Unity demo client.
//
// DEMO ONLY. This file is a transcription of the recipe the arbiter itself uses:
//
//   master       = SHA256(utf8(DemoPassphrase))                                    32 bytes
//   agent id     = hex(HMAC_SHA256(master, "agent-id:" + role + ":" + counter))[0..16]
//   agent key    = HMAC_SHA256(master, "agent-key:" + id)                          32 bytes
//   canonical(e) = v|a|s|t|r|c|m|k
//   signature    = hex(HMAC_SHA256(key, join("\n", canonical(each event))))
//
// The authoritative copies live on the server: shared/protocol.ts (PROTOCOL_VERSION and
// canonicalEvent) and server/agents.ts (derive and signEvent). tools/demo-agents.ts is a node
// port of the same recipe, and tests/unity-demo.test.ts asserts that port against the
// arbiter's own enrolment. So if the recipe ever changes on the server, that test fails and
// this file is known to be stale — rather than silently producing batches the arbiter rejects.
//
// No UnityEngine reference on purpose: the point of this file is that the bytes are decided
// here and nowhere else, and that it can be read without an editor.
//
// Measurements are integers in the demo. JavaScript renders a number with the shortest
// representation that round-trips, and .NET only agrees with that for values whose decimal
// form is exact — keeping `m` integral removes the one place the two runtimes could disagree
// on the string the MAC covers.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Zeus.Demo
{
    /// <summary>Ring as it travels on the wire. Matches ROLE_RING in shared/protocol.ts.</summary>
    public enum ZeusRing
    {
        Kmod = 0,
        Umon = 3,
        Srv = -1,
    }

    /// <summary>One telemetry sample. Field names are the wire names, one to two characters.</summary>
    public struct ZeusEvent
    {
        public int v;
        public string a;
        public string k;
        public uint s;
        public long t;
        public int r;
        public string c;
        public long m;
    }

    public static class ZeusWire
    {
        public const int ProtocolVersion = 1;
        public const int BatchMax = 64;

        /// <summary>Public by design. Not a credential, and never usable outside the demo.</summary>
        public const string DemoPassphrase = "zeus-unity-demo/loopback-only-not-a-production-secret";

        public static byte[] Sha256(string text)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return sha.ComputeHash(Encoding.UTF8.GetBytes(text));
            }
        }

        public static byte[] HmacSha256(byte[] key, string message)
        {
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
            }
        }

        /// <summary>
        /// Lowercase hex. The schema demands lowercase for the agent id and the subject digest;
        /// an uppercase digest is rejected before the MAC is even checked.
        /// </summary>
        public static string Hex(byte[] bytes)
        {
            StringBuilder builder = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2", CultureInfo.InvariantCulture));
            }
            return builder.ToString();
        }

        /// <summary>The demo master secret: 32 bytes from the published passphrase.</summary>
        public static byte[] DemoMaster()
        {
            return Sha256(DemoPassphrase);
        }

        /// <summary>Agent id for a (role, counter) pair — 16 lowercase hex characters.</summary>
        public static string AgentId(string role, int counter)
        {
            string digest = Hex(HmacSha256(DemoMaster(), "agent-id:" + role + ":" + Int(counter)));
            return digest.Substring(0, 16);
        }

        /// <summary>Per-agent MAC key — 32 bytes. Mirrors AgentRegistry.enroll().</summary>
        public static byte[] AgentKey(string id)
        {
            return HmacSha256(DemoMaster(), "agent-key:" + id);
        }

        /// <summary>
        /// Subject digest for a demo player — 32 lowercase hex. A digest, never an account
        /// identifier: the arbiter is never told who the player is.
        /// </summary>
        public static string Subject(string name)
        {
            return Hex(Sha256("zeus-unity-demo-subject:" + name)).Substring(0, 32);
        }

        /// <summary>The exact string the arbiter verifies. Field order is fixed: v|a|s|t|r|c|m|k.</summary>
        public static string Canonical(ZeusEvent e)
        {
            return string.Concat(
                Int(e.v), "|",
                e.a, "|",
                e.s.ToString(CultureInfo.InvariantCulture), "|",
                Long(e.t), "|",
                Int(e.r), "|",
                e.c, "|",
                Long(e.m), "|",
                e.k);
        }

        /// <summary>Batch canonical form: one event's canonical string per line, in order.</summary>
        public static string CanonicalBatch(List<ZeusEvent> events)
        {
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < events.Count; i++)
            {
                if (i > 0) builder.Append('\n');
                builder.Append(Canonical(events[i]));
            }
            return builder.ToString();
        }

        /// <summary>The MAC carried in the x-zeus-sig header.</summary>
        public static string Sign(byte[] key, string canonicalBatch)
        {
            return Hex(HmacSha256(key, canonicalBatch));
        }

        /// <summary>One event as JSON. The arbiter parses by key, so field order is free here.</summary>
        public static string Json(ZeusEvent e)
        {
            StringBuilder builder = new StringBuilder(96);
            builder.Append('{');
            builder.Append("\"v\":").Append(Int(e.v)).Append(',');
            builder.Append("\"a\":\"").Append(e.a).Append("\",");
            builder.Append("\"k\":\"").Append(e.k).Append("\",");
            builder.Append("\"s\":").Append(e.s.ToString(CultureInfo.InvariantCulture)).Append(',');
            builder.Append("\"t\":").Append(Long(e.t)).Append(',');
            builder.Append("\"r\":").Append(Int(e.r)).Append(',');
            builder.Append("\"c\":\"").Append(e.c).Append("\",");
            builder.Append("\"m\":").Append(Long(e.m));
            builder.Append('}');
            return builder.ToString();
        }

        /// <summary>The request body: a JSON array of one agent's events.</summary>
        public static string Body(List<ZeusEvent> events)
        {
            StringBuilder builder = new StringBuilder(128);
            builder.Append('[');
            for (int i = 0; i < events.Count; i++)
            {
                if (i > 0) builder.Append(',');
                builder.Append(Json(events[i]));
            }
            builder.Append(']');
            return builder.ToString();
        }

        // Invariant formatting is explicit everywhere: a client running under a locale that
        // formats 1000 as "1.000" would otherwise sign a different string than it sends, and
        // every batch would fail the MAC check with no clue why.
        private static string Int(int value)
        {
            return value.ToString(CultureInfo.InvariantCulture);
        }

        private static string Long(long value)
        {
            return value.ToString(CultureInfo.InvariantCulture);
        }
    }

    /// <summary>
    /// One reporting ring's identity on this client.
    ///
    /// The sequence counter belongs to the instance and must be strictly increasing: the
    /// arbiter refuses a repeat as a replay, and advancing it is the client's only ordering
    /// obligation — the arbiter's own clock is the ordering authority, never `t`.
    /// </summary>
    public sealed class ZeusAgent
    {
        public readonly string Role;
        public readonly int Counter;
        public readonly ZeusRing Ring;
        public readonly string Id;
        public readonly byte[] Key;

        private uint _seq;

        public ZeusAgent(string role, int counter, ZeusRing ring)
        {
            Role = role;
            Counter = counter;
            Ring = ring;
            Id = ZeusWire.AgentId(role, counter);
            Key = ZeusWire.AgentKey(Id);
        }

        /// <summary>Next sample for this ring, with its sequence number assigned.</summary>
        public ZeusEvent Next(string subject, string code, long measurement, long nowMs)
        {
            _seq += 1;
            ZeusEvent e = new ZeusEvent();
            e.v = ZeusWire.ProtocolVersion;
            e.a = Id;
            e.k = subject;
            e.s = _seq;
            e.t = nowMs;
            e.r = (int)Ring;
            e.c = code;
            e.m = measurement;
            return e;
        }

        /// <summary>Sequence counter as it stands. Exposed for logging only.</summary>
        public uint Sequence
        {
            get { return _seq; }
        }
    }
}
