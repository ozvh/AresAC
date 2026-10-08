using System;
using System.Collections.Generic;
using Ares.Demo;

public static class UnityWireRegression
{
    public static int Main()
    {
        AresAgent agent = new AresAgent("KMOD", 1, AresRing.Kmod);
        string subject = AresWire.Subject("unity-demo-player");
        AresEvent sample = agent.Next(subject, "X2", 1L, 1700000000000L);
        string canonical = AresWire.CanonicalBatch(new List<AresEvent> { sample });
        byte[] expectedKey = AresWire.AgentKey(agent.Id);
        string expectedSignature = AresWire.Sign(expectedKey, canonical);

        byte[] exposed = agent.Key;
        exposed[0] ^= 0xff;
        byte[] secondCopy = agent.Key;
        Array.Clear(secondCopy, 0, secondCopy.Length);
        if (Object.ReferenceEquals(exposed, agent.Key)) throw new Exception("key reference escaped");
        if (AresWire.Sign(agent.Key, canonical) != expectedSignature)
            throw new Exception("caller mutation changed signing state");
        if (agent.Next(subject, "X2", 1L, 1700000000001L).s != 2)
            throw new Exception("sequence behavior changed");

        // Consumed by Node assertions against the arbiter's independent implementation.
        Console.WriteLine(agent.Id);
        Console.WriteLine(canonical);
        Console.WriteLine(expectedSignature);
        return 0;
    }
}
