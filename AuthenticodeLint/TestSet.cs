using System;

namespace AuthenticodeLinter
{
    [Flags]
    public enum TestSet : byte
    {
        Modern = 0x01,
        Compat = 0x02,
        All = 0xFF
    }
}
