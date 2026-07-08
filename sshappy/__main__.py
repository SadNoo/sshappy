from __future__ import annotations

import asyncio

from .service import Service


def main() -> None:
    asyncio.run(Service().run())


if __name__ == "__main__":
    main()

