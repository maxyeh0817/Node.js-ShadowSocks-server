import http from "http";
import fs from "fs";
import path from "path";

const PORT = parseInt(process.env.SERVER_PORT || "20087");

const server = http.createServer((req, res) => {
  if (req.url === "/" || req.url === "/index.html") {
    const htmlPath = path.join(process.cwd(), "public", "index.html");
    fs.readFile(htmlPath, "utf-8", (err, data) => {
      if (err) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end("Internal Server Error");
        return;
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(data);
    });
  } else {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not Found");
  }
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
