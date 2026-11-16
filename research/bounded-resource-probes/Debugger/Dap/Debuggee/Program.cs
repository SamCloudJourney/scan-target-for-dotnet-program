using System;
using System.Threading;
Console.WriteLine("DEBUGGER_FIXTURE_STARTED");
int sentinel = 17;
Console.WriteLine("DEBUGGER_FIXTURE_MARKER_" + sentinel);
Thread.Sleep(9000);
Console.WriteLine("DEBUGGER_FIXTURE_FINISHED");
