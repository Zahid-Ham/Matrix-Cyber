import docker
import secrets
import time
import logging
from typing import Dict, Optional, List
from config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

class DockerExploitService:
    """
    Manages the lifecycle of vulnerable Docker containers for the Exploit Sandbox.
    """
    
    def __init__(self):
        try:
            self.client = docker.from_env()
            logger.info("Docker client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            self.client = None
            
        # Heartbeat Mechanism
        self.active_containers: Dict[str, float] = {} # container_id -> last_heartbeat_timestamp
        self.monitor_thread = None
        self.running = False
        self._start_monitor()

    def _start_monitor(self):
        """Starts the background thread to kill orphaned containers."""
        if self.running: 
            return
            
        import threading
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Sandbox heartbeat monitor started")

    def _monitor_loop(self):
        """Checks for inactive containers every 10 seconds."""
        import time
        while self.running:
            try:
                now = time.time()
                # Create a copy to iterate safely
                for container_id, last_seen in list(self.active_containers.items()):
                    if now - last_seen > 15: # 15 seconds timeout
                        logger.warning(f"Container {container_id} timed out (no heartbeat). Killing...")
                        self.stop_sandbox(container_id)
            except Exception as e:
                logger.error(f"Error in heartbeat monitor: {e}")
            time.sleep(10)

    def heartbeat(self, container_id: str):
        """Updates the last seen timestamp for a container."""
        if container_id in self.active_containers:
            self.active_containers[container_id] = time.time()
            return True
        return False

    def _get_image_for_vuln_type(self, vuln_type: str) -> str:
        """
        Maps vulnerability types to specific Docker images.
        """
        mapping = {
            "sql_injection": "matrix-sqli-lab:latest",
            "xss": "matrix-xss-lab:latest",
            "command_injection": "matrix-rce-lab:latest",
            "rce": "matrix-rce-lab:latest",
            "generic": "matrix-sqli-lab:latest"
        }
        return mapping.get(vuln_type, "matrix-sqli-lab:latest")

    def start_sandbox(self, vuln_type: str) -> Dict:
        """
        Starts a new isolated container for the given vulnerability type.
        """
        if not self.client:
            raise Exception("Docker service is not available")

        image_name = self._get_image_for_vuln_type(vuln_type)
        session_id = secrets.token_hex(8)
        container_name = f"matrix_sandbox_{session_id}"

        try:
            # Check if image exists locally
            try:
                self.client.images.get(image_name)
            except docker.errors.ImageNotFound:
                raise Exception(f"Sandbox image '{image_name}' not found. Please run 'docker build -t {image_name} ...'")

            # Start container with strict limits
            container = self.client.containers.run(
                image_name,
                name=container_name,
                detach=True,
                mem_limit="256m",  # Limit memory
                cpu_quota=50000,   # Limit CPU (50%)
                # Use bridge network for port access (localhost only)
                # For production: create custom network with firewall rules
                network_mode="bridge",  # Changed from "none" to allow port mapping
                ports={'80/tcp': None}, # Assign random host port
                environment={"SESSION_ID": session_id},
                auto_remove=True
            )
            
            # Wait for container to fully initialize networking
            time.sleep(2)
            
            # Reload to get assigned ports
            container.reload()
            
            # Get the mapped port (handle cases where port might not be ready yet)
            port_info = container.attrs.get('NetworkSettings', {}).get('Ports', {}).get('80/tcp')
            if port_info and len(port_info) > 0:
                host_port = port_info[0]['HostPort']
            else:
                # Fallback: container is running but port info not available yet
                host_port = "8080"  # Default fallback
                logger.warning(f"Port info not available for container {container.id}, using default port {host_port}")
            
            # Register for heartbeat
            self.active_containers[container.id] = time.time()

            return {
                "session_id": session_id,
                "container_id": container.id,
                "url": f"{settings.base_url}:{host_port}",
                "status": "running",
                "type": vuln_type
            }

        except Exception as e:
            logger.error(f"Failed to start sandbox: {e}")
            raise e

    def stop_sandbox(self, container_id: str):
        """
        Stops and removes the sandbox container.
        """
        # Remove from monitoring first to prevent concurrent kills
        if container_id in self.active_containers:
            del self.active_containers[container_id]

        if not self.client:
            return

        try:
            container = self.client.containers.get(container_id)
            logger.info(f"Terminating sandbox container: {container_id}")
            
            # Try to kill (instant stop)
            try:
                container.kill()
            except Exception as e:
                logger.warning(f"Failed to kill container {container_id}, it might be stopped already. Error: {e}")
            
            # Always force remove
            try:
                container.remove(force=True)
                logger.info(f"Successfully removed container: {container_id}")
                return True
            except Exception as e:
                logger.error(f"Failed to remove container {container_id}: {e}")
                
                # Double check if it's gone
                try:
                    self.client.containers.get(container_id)
                    # If we can still get it, it failed
                    return False
                except docker.errors.NotFound:
                    # It's gone, so we succeeded
                    print(f"Container {container_id} not found, assuming removed.")
                    return True

        except docker.errors.NotFound:
            logger.warning(f"Container {container_id} not found during stop request (already gone).")
            return True # Treat as success
        except Exception as e:
            logger.error(f"Critical error stopping sandbox {container_id}: {e}")
            raise e

    def get_logs(self, container_id: str, tail: int = 50) -> str:
        """
        Retrieves logs from the container (simulating terminal output).
        """
        if not self.client:
            return ""
        
        # Update heartbeat if interacting
        self.heartbeat(container_id)

        try:
            container = self.client.containers.get(container_id)
            return container.logs(tail=tail).decode('utf-8')
        except Exception as e:
            logger.error(f"Error getting logs: {e}")
            return ""

    def execute_command(self, container_id: str, cmd: str) -> str:
        """
        Executes a command inside the container and returns output.
        Useful for 'Terminal' style interaction in the UI.
        """
        if not self.client:
            return "Docker service unavailable"

        # Update heartbeat
        self.heartbeat(container_id)

        try:
            container = self.client.containers.get(container_id)
            # exec_run returns (exit_code, output)
            # Wrap in sh -c to allow pipes, redirects, and complex commands
            exit_code, output = container.exec_run(["/bin/sh", "-c", cmd])
            return output.decode('utf-8')
        except Exception as e:
            return f"Error executing command: {e}"

# Singleton instance
docker_service = DockerExploitService()
