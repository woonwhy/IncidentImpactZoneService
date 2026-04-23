let zones = [];

const API_BASE_URL = "https://5ylw50ho8h.execute-api.us-east-1.amazonaws.com";

const searchInput = document.getElementById("search");
const severitySelect = document.getElementById("severity");
const statusSelect = document.getElementById("status");
const incidentTypeSelect = document.getElementById("incidentType");
const zoneTable = document.getElementById("zoneTable");
const zoneDetail = document.getElementById("zoneDetail");

const map = L.map("map").setView([13.736717, 100.523186], 6);

L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
  maxZoom: 18,
  attribution: "&copy; OpenStreetMap contributors",
}).addTo(map);

let mapMarkers = [];
let mapCircles = [];

async function fetchZones() {
  try {
    const severity = severitySelect.value;
    const params = new URLSearchParams();

    if (severity && severity !== "ALL") {
      params.set("severityLevel", severity);
    }

    const url = `${API_BASE_URL}/impact-zones${
      params.toString() ? `?${params.toString()}` : ""
    }`;

    const response = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    zones = Array.isArray(data.items) ? data.items : [];
  } catch (error) {
    console.error("โหลดข้อมูล impact zones ไม่สำเร็จ:", error);
    zones = [];
    zoneDetail.innerHTML = "ไม่สามารถโหลดข้อมูลจาก API ได้";
  }
}

function badgeClass(type, value) {
  if (type === "severity") return "badge-" + value.toLowerCase();
  return "badge-" + value.toLowerCase();
}

function formatDate(value) {
  return new Date(value).toLocaleString("th-TH");
}

function getMarkerColor(severityLevel) {
  switch (severityLevel) {
    case "CRITICAL":
      return "#dc2626";
    case "HIGH":
      return "#ea580c";
    case "MEDIUM":
      return "#ca8a04";
    case "LOW":
      return "#16a34a";
    default:
      return "#2563eb";
  }
}

function getCircleStyle(severityLevel) {
  switch (severityLevel) {
    case "CRITICAL":
      return {
        color: "#dc2626",
        fillColor: "#dc2626",
        fillOpacity: 0.15,
        weight: 1.5,
      };
    case "HIGH":
      return {
        color: "#ea580c",
        fillColor: "#ea580c",
        fillOpacity: 0.12,
        weight: 1.5,
      };
    case "MEDIUM":
      return {
        color: "#ca8a04",
        fillColor: "#ca8a04",
        fillOpacity: 0.1,
        weight: 1.5,
      };
    case "LOW":
      return {
        color: "#16a34a",
        fillColor: "#16a34a",
        fillOpacity: 0.08,
        weight: 1.5,
      };
    default:
      return {
        color: "#2563eb",
        fillColor: "#2563eb",
        fillOpacity: 0.1,
        weight: 1.5,
      };
  }
}

function getAffectedRadius(zone) {
  switch (zone.severityLevel) {
    case "CRITICAL":
      return 12000;
    case "HIGH":
      return 8000;
    case "MEDIUM":
      return 5000;
    case "LOW":
      return 2500;
    default:
      return 3000;
  }
}

function getStatusOpacity(status) {
  switch (status) {
    case "ACTIVE":
      return 0.9;
    case "CONTAINED":
      return 0.6;
    case "RESOLVED":
      return 0.4;
    case "ARCHIVED":
      return 0.2;
    default:
      return 0.8;
  }
}

function showDetail(zone) {
  zoneDetail.innerHTML = `
    <p><strong>ID:</strong> ${zone.id}</p>
    <p><strong>Incident Type:</strong> ${zone.incidentType}</p>
    <p><strong>Severity Level:</strong> <span class="badge ${badgeClass("severity", zone.severityLevel)}">${zone.severityLevel}</span></p>
    <p><strong>Status:</strong> <span class="badge ${badgeClass("status", zone.status)}">${zone.status}</span></p>
    <p><strong>Center Point:</strong> lat ${zone.centerPoint?.lat ?? "-"}, lng ${zone.centerPoint?.lng ?? "-"}</p>
    <p><strong>Reported Time:</strong> ${formatDate(zone.reportedTime)}</p>
    <p><strong>Last Updated:</strong> ${formatDate(zone.lastUpdated)}</p>
    <p><strong>Estimated Affected Population:</strong> ${Number(zone.estimatedAffectedPopulation || 0).toLocaleString()} คน</p>
    <p><strong>Evacuation Required:</strong> ${zone.evacuationRequired ? "Yes" : "No"}</p>
    <p><strong>Affected Radius:</strong> ${(getAffectedRadius(zone) / 1000).toFixed(1)} km</p>
  `;
}

function addAffectedAreaCircle(zone) {
  const lat = zone.centerPoint?.lat;
  const lng = zone.centerPoint?.lng;

  if (typeof lat !== "number" || typeof lng !== "number") {
    return null;
  }

  const circle = L.circle([lat, lng], {
    radius: getAffectedRadius(zone),
    ...getCircleStyle(zone.severityLevel),
    fillOpacity: getStatusOpacity(zone.status) * 0.3,
  });

  circle.bindPopup(`
    <strong>${zone.id}</strong><br>
    ${zone.incidentType}<br>
    Affected radius: ${(getAffectedRadius(zone) / 1000).toFixed(1)} km
  `);

  circle.on("click", () => showDetail(zone));
  circle.addTo(map);

  return circle;
}

function renderMarkers(filteredZones) {
  mapMarkers.forEach((marker) => map.removeLayer(marker));
  mapCircles.forEach((circle) => map.removeLayer(circle));
  mapMarkers = [];
  mapCircles = [];

  filteredZones.forEach((zone) => {
    const lat = zone.centerPoint?.lat;
    const lng = zone.centerPoint?.lng;

    const circle = addAffectedAreaCircle(zone);
    if (circle) {
      mapCircles.push(circle);
    }

    if (typeof lat === "number" && typeof lng === "number") {
      const marker = L.circleMarker([lat, lng], {
        radius: 8,
        color: getMarkerColor(zone.severityLevel),
        fillColor: getMarkerColor(zone.severityLevel),
        fillOpacity: getStatusOpacity(zone.status),
        weight: 2,
      }).addTo(map);

      marker.bindPopup(`
        <strong>${zone.id}</strong><br>
        ${zone.incidentType}<br>
        Severity: ${zone.severityLevel}<br>
        Status: ${zone.status}
      `);

      marker.on("click", () => showDetail(zone));
      mapMarkers.push(marker);
    }
  });

  const layers = [...mapMarkers, ...mapCircles];

  if (layers.length > 0) {
    const group = L.featureGroup(layers);
    map.fitBounds(group.getBounds(), { padding: [30, 30] });
  } else {
    map.setView([13.736717, 100.523186], 6);
  }
}

function renderTable(filteredZones) {
  zoneTable.innerHTML = "";

  filteredZones.forEach((zone) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${zone.id}</td>
      <td>${zone.incidentType}</td>
      <td><span class="badge ${badgeClass("severity", zone.severityLevel)}">${zone.severityLevel}</span></td>
      <td><span class="badge ${badgeClass("status", zone.status)}">${zone.status}</span></td>
      <td>${Number(zone.estimatedAffectedPopulation || 0).toLocaleString()}</td>
    `;
    row.style.cursor = "pointer";
    row.onclick = () => {
      showDetail(zone);

      const lat = zone.centerPoint?.lat;
      const lng = zone.centerPoint?.lng;

      if (typeof lat === "number" && typeof lng === "number") {
        const bounds = L.circle([lat, lng], {
          radius: getAffectedRadius(zone),
        }).getBounds();

        map.fitBounds(bounds, { padding: [30, 30] });
      }
    };
    zoneTable.appendChild(row);
  });
}

async function applyFilters(fetchFromApi = false) {
  if (fetchFromApi) {
    await fetchZones();
  }

  const search = searchInput.value.toLowerCase();
  const severity = severitySelect.value;
  const status = statusSelect.value;
  const incidentType = incidentTypeSelect.value;

  const filteredZones = zones.filter((zone) => {
    const matchSearch =
      zone.id?.toLowerCase().includes(search) ||
      zone.incidentType?.toLowerCase().includes(search);
    const matchSeverity = severity === "ALL" || zone.severityLevel === severity;
    const matchStatus = status === "ALL" || zone.status === status;
    const matchIncidentType =
      incidentType === "ALL" || zone.incidentType === incidentType;

    return matchSearch && matchSeverity && matchStatus && matchIncidentType;
  });

  renderMarkers(filteredZones);
  renderTable(filteredZones);

  if (filteredZones.length > 0) {
    showDetail(filteredZones[0]);
  } else if (zones.length > 0) {
    zoneDetail.innerHTML = "ไม่พบข้อมูล zone ตามเงื่อนไขที่เลือก";
  } else {
    zoneDetail.innerHTML = "ไม่พบข้อมูลจาก API";
  }
}

searchInput.addEventListener("input", () => applyFilters(false));
statusSelect.addEventListener("change", () => applyFilters(false));
incidentTypeSelect.addEventListener("change", () => applyFilters(false));
severitySelect.addEventListener("change", () => applyFilters(true));

applyFilters(true);