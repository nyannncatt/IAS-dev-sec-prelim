const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const axios = require("axios");
const fs = require("fs");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const port = process.env.PORT || 3000;

app.use(express.json());
app.set("view engine", "hbs");
app.use(express.urlencoded({ extended: false }));

const templatePath = path.join(__dirname, "../templates");
const publicPath = path.join(__dirname, "../public");
const scriptsPath = path.join(__dirname, "../scripts");

app.set("views", templatePath);
app.use(express.static(publicPath));
app.use(express.static(scriptsPath));

app.get("/", (req, res) => {
  res.render("index");
});

let lastIndex = 0;
const apiKey1 = "Ty2f2YTRIkOUpSmZkkRjRmsJr6pjShSV";
const apiKey2 = "ZBks6PJ6EE1bWnw6iFchWcQSux8Xap7h";
const apiKey3 = "N37AXPb8giUKEaHYMzVVgYax2w6cGMmh";
const apiKey4 = "zqNfM9XFi6OUjD2tjpDlbQGRlr8sPNFQ";
const apiKey5 = "T07GaOzAHDRkSZtaIETmf8cpqvWjHkJE";
const apiKey = apiKey1;

function readUrlsFromFile(filePath) {
  try {
    const urls = fs.readFileSync(filePath, "utf-8").trim().split("\n");
    return urls;
  } catch (error) {
    console.error("Error reading URLs from file:", error);
    return [];
  }
}

async function verifyUrls(urls) {
  const results = [];

  for (let i = lastIndex; i < urls.length; i++) {
    const url = urls[i];
    try {
      const urlResponse = await axios.get(
        `https://www.ipqualityscore.com/api/json/url/${apiKey}/${encodeURIComponent(
          url
        )}`
      );
      const isMalicious = urlResponse.data.suspicious;
      const riskscore = urlResponse.data.risk_score;
      const phishing = urlResponse.data.phishing;
      const malware = urlResponse.data.malware;
      const spam = urlResponse.data.spam;
      const adult = urlResponse.data.adult;
      const category = urlResponse.data.category;

      // Only push to results if suspicious
      if (isMalicious) {
        results.push({
          url,
          riskscore,
          phishing,
          malware,
          spam,
          adult,
          category,
        });
        fs.appendFileSync('suspicious_urls.txt', `${url}\n`);
      }
    } catch (error) {
      console.error("Error verifying URL:", error);
      results.push({ url, error: "Error verifying URL" });
    }
  }

  return results;
}

async function verifyIPs(ips) {
  const ipResults = [];

  for (const ip of ips) {
    try {
      const ipResponse = await axios.get(
        `https://ipqualityscore.com/api/json/ip/${apiKey}/${encodeURIComponent(
          ip
        )}`
      );
      const {
        host,
        fraud_score,
        recent_abuse,
        latitude,
        longitude,
        city,
        region,
      } = ipResponse.data;

      // Only push the result if fraud score is greater than 50
      if (fraud_score > 50) {
        ipResults.push({
          ip,
          host,
          fraud_score,
          recent_abuse,
          latitude,
          longitude,
          city,
          region,
        });
        fs.appendFileSync('suspicious_ips.txt', `${ip}\n`);
      }
    } catch (error) {
      console.error("Error verifying IP:", error);
      ipResults.push({ ip, error: "Error verifying IP" });
    }
  }

  return ipResults;
}

io.on("connection", (socket) => {
  console.log("User connected");

  // Example usage
  const urlFilePath = "D:\\TechtonicShift\\Pcap\\extracted_uris.txt";
  const ipFilePath = "D:\\TechtonicShift\\Pcap\\extracted_ip_addresses.txt";
  const urls = readUrlsFromFile(urlFilePath);
  const ips = readUrlsFromFile(ipFilePath);

  Promise.all([verifyUrls(urls), verifyIPs(ips)])
    .then(([urlResults, ipResults]) => {
      console.log("URL verification results:", urlResults);
      console.log("IP verification results:", ipResults);
      // Send both suspicious URLs and IP addresses to frontend
      socket.emit("verificationResults", { urls: urlResults, ips: ipResults });
    })
    .catch((error) => {
      console.error("Error:", error);
    });
});

server.listen(port, () => {
  console.log("Server running on port", port);
});

