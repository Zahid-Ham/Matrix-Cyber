"""
Graceful Shutdown Manager for Matrix Security Scanner.

Handles SIGTERM/SIGINT signals and ensures clean resource cleanup.
"""
import asyncio
import signal
import logging
from typing import List, Set, Callable, Awaitable
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


class ShutdownManager:
    """
    Manages graceful shutdown of async tasks and resources.
    
    Usage:
        manager = ShutdownManager()
        manager.register_task(some_async_task)
        manager.register_cleanup(cleanup_function)
        
        # On shutdown (e.g., SIGTERM):
        await manager.shutdown()
    """
    
    def __init__(self):
        self._tasks: Set[asyncio.Task] = set()
        self._cleanup_handlers: List[Callable[[], Awaitable[None]]] = []
        self._shutdown_event = asyncio.Event()
        self._is_shutting_down = False
    
    def register_task(self, task: asyncio.Task) -> None:
        """
        Register an async task for tracking.
        
        Args:
            task: The asyncio.Task to track.
        """
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
    
    def register_cleanup(self, handler: Callable[[], Awaitable[None]]) -> None:
        """
        Register a cleanup handler to run on shutdown.
        
        Args:
            handler: An async function to call during cleanup.
        """
        self._cleanup_handlers.append(handler)
    
    @property
    def is_shutting_down(self) -> bool:
        """Check if shutdown is in progress."""
        return self._is_shutting_down
    
    async def wait_for_shutdown(self) -> None:
        """Block until shutdown signal is received."""
        await self._shutdown_event.wait()
    
    async def shutdown(self, timeout: float = 10.0) -> None:
        """
        Initiate graceful shutdown.
        
        Args:
            timeout: Maximum time to wait for tasks to complete.
        """
        if self._is_shutting_down:
            logger.warning("Shutdown already in progress")
            return
        
        self._is_shutting_down = True
        self._shutdown_event.set()
        logger.info("Initiating graceful shutdown...")
        
        # Cancel all tracked tasks
        pending_tasks = list(self._tasks)
        if pending_tasks:
            logger.info(f"Cancelling {len(pending_tasks)} pending tasks...")
            for task in pending_tasks:
                task.cancel()
            
            # Wait for tasks to complete cancellation
            try:
                await asyncio.wait_for(
                    asyncio.gather(*pending_tasks, return_exceptions=True),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"Some tasks did not complete within {timeout}s timeout")
        
        # Run cleanup handlers
        logger.info(f"Running {len(self._cleanup_handlers)} cleanup handlers...")
        for handler in self._cleanup_handlers:
            try:
                await handler()
            except Exception as e:
                logger.error(f"Cleanup handler failed: {e}")
        
        logger.info("Shutdown complete")


# Global instance for convenience
_shutdown_manager: ShutdownManager = None


def get_shutdown_manager() -> ShutdownManager:
    """Get or create the global ShutdownManager instance."""
    global _shutdown_manager
    if _shutdown_manager is None:
        _shutdown_manager = ShutdownManager()
    return _shutdown_manager


def setup_signal_handlers(loop: asyncio.AbstractEventLoop = None) -> None:
    """
    Install signal handlers for graceful shutdown.
    
    Args:
        loop: The event loop to use. Defaults to the running loop.
    """
    if loop is None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()
    
    manager = get_shutdown_manager()
    
    def handle_signal(signum):
        logger.info(f"Received signal {signum}, initiating shutdown...")
        asyncio.create_task(manager.shutdown())
    
    # Note: signal.SIGTERM is not available on Windows in the same way
    try:
        loop.add_signal_handler(signal.SIGTERM, lambda: handle_signal(signal.SIGTERM))
        loop.add_signal_handler(signal.SIGINT, lambda: handle_signal(signal.SIGINT))
        logger.info("Signal handlers installed for SIGTERM and SIGINT")
    except NotImplementedError:
        # Windows doesn't support add_signal_handler
        logger.warning("Signal handlers not available on this platform")


@asynccontextmanager
async def managed_shutdown():
    """
    Context manager that ensures graceful shutdown on exit.
    
    Usage:
        async with managed_shutdown():
            await run_scanner()
    """
    manager = get_shutdown_manager()
    
    try:
        yield manager
    finally:
        if not manager.is_shutting_down:
            await manager.shutdown()
