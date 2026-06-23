import docker

client = docker.from_env()
container = client.containers.get('web_demo233')
local_file = "./test"
container_file = "/home/web_demo233/"
container.put_archive(container_file, local_file)