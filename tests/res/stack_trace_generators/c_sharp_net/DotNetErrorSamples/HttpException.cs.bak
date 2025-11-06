using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace DotNetErrorSamples
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("Simulating downstream HTTP API failure...");
            await CallDownstreamApiAsync();
        }

        static async Task CallDownstreamApiAsync()
        {
            // In a real app, HttpClient would be injected.
            using var client = new HttpClient();

            // Use an obviously invalid URL so we fail fast.
            var url = "http://[::1]:abc"; // invalid port -> HttpRequestException

            HttpResponseMessage resp = await client.GetAsync(url);
            Console.WriteLine("Status: " + (int)resp.StatusCode);
        }
    }
}

