//const { response } = require("express");

const socket = io();

socket.on("verificationResults", (results) => {
  displayResults(results);
});

document.getElementById("generatePdfBtn").addEventListener("click", () => {
  // Get the HTML content of the webpage
  let htmlContent = document.documentElement.outerHTML;

  // Exclude the navbar from the HTML content
  const navbar = document.querySelector(".navbar");
  const footer = document.querySelector(".footer");
  const gbutton = document.querySelector(".gbutton");
  const showBlocked = document.getElementById("showBlocked")
  if (navbar) {
    htmlContent = htmlContent.replace(navbar.outerHTML, "");
  }
  if (footer) {
    htmlContent = htmlContent.replace(footer.outerHTML, "");
  }
  if (gbutton) {
    htmlContent = htmlContent.replace(gbutton.outerHTML, "");
  }
  if (showBlocked) {
    htmlContent = htmlContent.replace(showBlocked.outerHTML, "");
  }

  // Create a new window to render the HTML content
  const pdfWindow = window.open("", "_blank");

  // Render the HTML content in the new window
  pdfWindow.document.open();
  pdfWindow.document.write(`
    <html>
      <head>
        <title>Network Log Report</title>
      </head>
      <body>
        <h1 class="nlr">Network Log Report</h1>
        ${htmlContent}
      </body>
    </html>
  `);
  pdfWindow.document.close();

  // Wait for the content to be fully loaded, then generate the PDF
  setTimeout(() => {
    pdfWindow.print();
  }, 1000); // Adjust the delay as needed to ensure the content is fully loaded before printing
});

function displayResults(results) {
  const urlContainer = document.getElementById("resultsUrl");
  const ipContainer = document.getElementById("resultsIp");

  // Check if there are any suspicious URLs
  if (results.urls.length > 0) {
    // Store URL results in session storage
    sessionStorage.setItem("suspiciousUrls", JSON.stringify(results.urls));
    // Display URL results
    displayUrls(results.urls, urlContainer);
  } else {
    // If no suspicious URLs, display message
    urlContainer.textContent = "No suspicious URLs detected.";
  }

  // Check if there are any IP verification results
  if (results.ips.length > 0) {
    // Store IP results in session storage
    sessionStorage.setItem("suspiciousIPs", JSON.stringify(results.ips));
    // Display IP results
    displayIPs(results.ips, ipContainer);
  } else {
    // If no IP verification results, display message
    ipContainer.textContent = "No suspicious IPs detected.";
  }
}

function displayUrls(urls, container) {
  // Clear existing content
  container.innerHTML = "";
  // Create card for suspicious URLs
  const cardDiv = document.createElement("div");
  cardDiv.classList.add("card", "mt-3");

  const cardHeader = document.createElement("div");
  cardHeader.classList.add("card-header");
  cardHeader.textContent = "Suspicious URLs Detected";
  cardDiv.appendChild(cardHeader);

  const cardBody = document.createElement("div");
  cardBody.classList.add("card-body");

  const listGroup = document.createElement("ul");
  listGroup.classList.add("list-group");

  // Iterate through each result and display in the card
  urls.forEach((result, index) => {
    const listItem = document.createElement("li");
    listItem.classList.add("list-group-item");

    // Display URL
    const urlParagraph = document.createElement("p");
    urlParagraph.classList.add("url_paragraph");
    urlParagraph.textContent = result.url;
    listItem.appendChild(urlParagraph);

    // Display Risk Score with bold heading on the same line
    const riskScoreHeading = document.createElement("span");
    riskScoreHeading.innerHTML = "<b>Risk Score:</b> ";
    listItem.appendChild(riskScoreHeading);

    const riskScoreText = document.createTextNode(result.riskscore);
    listItem.appendChild(riskScoreText);

    // Display Phishing
    const phishingText = document.createElement("p");
    phishingText.innerHTML = `<b>Phishing:</b> ${result.phishing}`;
    listItem.appendChild(phishingText);

    // Display Malware
    const malwareText = document.createElement("p");
    malwareText.innerHTML = `<b>Malware:</b> ${result.malware}`;
    listItem.appendChild(malwareText);

    // Display Spam
    const spamText = document.createElement("p");
    spamText.innerHTML = `<b>Spam:</b> ${result.spam}`;
    listItem.appendChild(spamText);

    // Display Adult
    const adultText = document.createElement("p");
    adultText.innerHTML = `<b>Adult:</b> ${result.adult}`;
    listItem.appendChild(adultText);

    // Display Category
    const categoryText = document.createElement("p");
    categoryText.innerHTML = `<b>Category:</b> ${result.category}`;
    listItem.appendChild(categoryText);

    listGroup.appendChild(listItem);

    cardBody.appendChild(listGroup);
    cardDiv.appendChild(cardBody);

    container.appendChild(cardDiv);
  });
}

function displayIPs(ips, container) {
  // Clear existing content
  container.innerHTML = "";
  // Create card for suspicious URLs
  const cardDiv = document.createElement("div");
  cardDiv.classList.add("card", "mt-3");

  const cardHeader = document.createElement("div");
  cardHeader.classList.add("card-header");
  cardHeader.textContent = "Suspicious IPs Detected";
  cardDiv.appendChild(cardHeader);

  const cardBody = document.createElement("div");
  cardBody.classList.add("card-body");

  const listGroup = document.createElement("ul");
  listGroup.classList.add("list-group");

  // Iterate through each result and display in the card
  ips.forEach((result, index) => {
    const listItem = document.createElement("li");
    listItem.classList.add("list-group-item");

    // Display IP
    const ipParagraph = document.createElement("p");
    ipParagraph.classList.add("ip_paragraph");
    ipParagraph.textContent = result.ip;
    listItem.appendChild(ipParagraph);

    // Display Host
    const hostText = document.createElement("p");
    hostText.innerHTML = `<b>Host:</b> ${result.host}`;
    listItem.appendChild(hostText);

    // Display Fraud Score
    const fraudScoreText = document.createElement("p");
    fraudScoreText.innerHTML = `<b>Fraud Score:</b> ${result.fraud_score}`;
    listItem.appendChild(fraudScoreText);

    // Display Recent Abuse
    const recentAbuseText = document.createElement("p");
    recentAbuseText.innerHTML = `<b>Recent Abuse:</b> ${result.recent_abuse}`;
    listItem.appendChild(recentAbuseText);

    // Display Latitude
    const latitudeText = document.createElement("p");
    latitudeText.innerHTML = `<b>Latitude:</b> ${result.latitude}`;
    listItem.appendChild(latitudeText);

    // Display Longitude
    const longitudeText = document.createElement("p");
    longitudeText.innerHTML = `<b>Longitude:</b> ${result.longitude}`;
    listItem.appendChild(longitudeText);

    // Display City
    const cityText = document.createElement("p");
    cityText.innerHTML = `<b>City:</b> ${result.city}`;
    listItem.appendChild(cityText);

    // Display Region
    const regionText = document.createElement("p");
    regionText.innerHTML = `<b>Region:</b> ${result.region}`;
    listItem.appendChild(regionText);

    listGroup.appendChild(listItem);
    cardBody.appendChild(listGroup);
    cardDiv.appendChild(cardBody);
    container.appendChild(cardDiv);
  });
}

// Function to fetch predictions from Flask endpoint
function fetchPredictions() {
  fetch("http://127.0.0.1:5000/results")
    .then((response) => response.json())
    .then((data) => {
      // Process the predictions here
      displayPredictions(data.rf_prediction, data.timestamps); // Access predictions from 'rf_prediction' key
    })
    .catch((error) => {
      console.error("Error fetching predictions:", error);
    });
}

// Function to refresh predictions every 30 seconds
function refreshPredictions() {
  setInterval(fetchPredictions, 30000); // Call fetchPredictions every 30 seconds
}

// Mapping of attack types to their descriptions
const ATTACK_TYPE_MAPPING = {
  dos: "Probable DOS Attack",
  r2l: "Root to Local Attack Detected",
  u2r: "User to Root Attack Detected",
  probe: "Probe Attack Detected",
  normal: "Normal Traffic",
};

// Function to display predictions on the webpage
function displayPredictions(predictions, timestamps) {
  const iocContainer = document.getElementById("resultsIoc");

  // Clear existing content
  iocContainer.innerHTML = "";

  // Create card for predictions
  const cardDiv = document.createElement("div");
  cardDiv.classList.add("card", "mt-3");

  const cardHeader = document.createElement("div");
  cardHeader.classList.add("card-header");
  cardHeader.textContent = "Suspicious Inbound Connections Detection";
  cardDiv.appendChild(cardHeader);

  const cardBody = document.createElement("div");
  cardBody.classList.add("card-body");

  // Create table
  const table = document.createElement("table");
  table.classList.add("table", "table-hover", "IOCTable", "table-dark");

  // Create table header
  const thead = document.createElement("thead");
  const headerRow = document.createElement("tr");
  const headers = ["S. No", "Time of Capture", "Threat Details"];
  headers.forEach((headerText) => {
    const th = document.createElement("th");
    th.textContent = headerText;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);
  table.appendChild(thead);

  // Create table body
  const tbody = document.createElement("tbody");

  // Iterate through each prediction and add to the table
  predictions.forEach((prediction, index) => {
    const row = document.createElement("tr");

    // Add Sno
    const snoCell = document.createElement("td");
    snoCell.textContent = index + 1;
    row.appendChild(snoCell);

    // Add Time
    const timeCell = document.createElement("td");
    timeCell.textContent = timestamps[index];
    row.appendChild(timeCell);

    // Add Threat Details with mapped descriptions
    const threatDetailsCell = document.createElement("td");
    const mappedDescription =
      ATTACK_TYPE_MAPPING[prediction.toLowerCase()] || prediction;
    threatDetailsCell.textContent = mappedDescription;
    row.appendChild(threatDetailsCell);

    // Add custom class based on prediction type
    row.classList.add(prediction.toLowerCase());

    tbody.appendChild(row);
  });

  table.appendChild(tbody);
  cardBody.appendChild(table);
  cardDiv.appendChild(cardBody);
  iocContainer.appendChild(cardDiv);
}

// Retrieve and display stored results on page load
window.addEventListener("load", () => {
  fetchPredictions(); // Fetch and display predictions when the page loads
  refreshPredictions();

  const storedUrls = sessionStorage.getItem("suspiciousUrls");
  if (storedUrls) {
    displayUrls(JSON.parse(storedUrls), document.getElementById("resultsUrl"));
  }

  const storedIPs = sessionStorage.getItem("suspiciousIPs");
  if (storedIPs) {
    displayIPs(JSON.parse(storedIPs), document.getElementById("resultsIp"));
  }
});

document.getElementById("showBlocked").addEventListener("click", () => {
  fetchBlockedConnections();
});

function fetchBlockedConnections() {
  const blockedUrls = ["http://www.artedesignsas.it/favicon.ico", "http://www.artedesignsas.it/catalogo.html?page=shop.browse&category_id=14"]; // Example array of blocked URLs
  const blockedIPs = ["147.0.191.243", "44.194.35.87", "192.168.11.4", "20.54.232.160"]; // Example array of blocked IPs
  displayBlockedUrls(blockedUrls);
  displayBlockedIPs(blockedIPs);
}

function displayBlockedUrls(blockedUrls) {
  const blockedUrlsList = document.getElementById("blockedUrls");
  blockedUrlsList.innerHTML = "";
  blockedUrls.forEach((url) => {
    const listItem = document.createElement("li");
    listItem.textContent = url;
    listItem.classList.add("list-group-item");
    blockedUrlsList.appendChild(listItem);
  });
}

function displayBlockedIPs(blockedIPs) {
  const blockedIPsList = document.getElementById("blockedIPs");
  blockedIPsList.innerHTML = "";
  blockedIPs.forEach((ip) => {
    const listItem = document.createElement("li");
    listItem.textContent = ip;
    listItem.classList.add("list-group-item");
    blockedIPsList.appendChild(listItem);
  });
}
