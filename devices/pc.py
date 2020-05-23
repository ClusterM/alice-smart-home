import subprocess

def pc_query(capability_type, instance):
    if capability_type == "devices.capabilities.on_off":
        p = subprocess.run(["ping", "-c", "1", "192.168.0.2"], stdout=subprocess.PIPE)
        state = p.returncode == 0
        return state

def pc_action(capability_type, instance, value, relative):
    if capability_type == "devices.capabilities.on_off":
        if value:
            subprocess.run(["wakeonlan", "-i", "192.168.0.255", "00:11:22:33:44:55"])
        else:
            subprocess.run(["sh", "-c", "echo shutdown -h | ssh clust@192.168.0.2"])
        return "DONE"
