import asyncio

async def handler():
    await asyncio.sleep(0.1)
    raise RuntimeError("Simulated async handler failure")

if __name__ == "__main__":
    # Forget to use asyncio.run() — typical async misuse
    handler()
