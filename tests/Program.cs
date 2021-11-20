
namespace tests
{
    using HalfSipHash;
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Testing!");
            Tests.TestCaseHashAlgorithm();
            Console.WriteLine("All passed");

            Console.WriteLine();
            
            Console.WriteLine("Performance testing!");

            var perfTestRounds = 100000;
            
            Tests.TestPerformanceHashAlgorithm(perfTestRounds);
            Console.WriteLine();
            Console.WriteLine("All Done!");
        }
    }
}