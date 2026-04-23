import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  QueryCommand,
  PutCommand,
  UpdateCommand,
  GetCommand,
  ScanCommand,
} from "@aws-sdk/lib-dynamodb";
import { randomUUID } from "crypto";

const client = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const TABLE = "ImpactZones";
const INDEX = "status-severity-index";

// ─── External Service URLs ────────────────────────────────────────────────────
const INCIDENT_REPORTER_URL =
  process.env.INCIDENT_REPORTER_URL ?? "https://8wbns0ueuj.execute-api.us-east-1.amazonaws.com/v1";

// ─── Timeout / Retry config ──────────────────────────────────────────────────
const OUTBOUND_TIMEOUT_MS = 1500;
const OUTBOUND_MAX_ATTEMPTS = 2;

// ─── Status flow validation ───────────────────────────────────────────────────
const STATUS_ORDER = ["ACTIVE", "CONTAINED", "RESOLVED", "ARCHIVED"];

function isValidStatusTransition(current, next) {
  return STATUS_ORDER.indexOf(next) >= STATUS_ORDER.indexOf(current);
}

// ─── CORS / JSON helper ───────────────────────────────────────────────────────
function jsonResponse(statusCode, data, traceId) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Methods": "GET,POST,PATCH,OPTIONS",
    },
    body: JSON.stringify({
      traceId,
      ...data,
    }),
  };
}

// ─── Auto-compute fields from incidentType ───────────────────────────────────
function computeFields(incidentType, centerPoint) {
  const { lat, lng } = centerPoint;
  const delta = 0.04;

  const sevMap = { flood: "HIGH", fire: "CRITICAL", earthquake: "MEDIUM" };
  const popMap = { flood: 2800, fire: 5100, earthquake: 1600 };

  const severityLevel = sevMap[incidentType] ?? "MEDIUM";
  const estimatedAffectedPopulation = popMap[incidentType] ?? 1000;
  const evacuationRequired = ["CRITICAL", "HIGH"].includes(severityLevel);

  const affectedArea = {
    type: "Polygon",
    coordinates: [[
      [lng - delta, lat - delta],
      [lng + delta, lat - delta],
      [lng + delta, lat + delta],
      [lng - delta, lat + delta],
    ]],
  };

  return {
    severityLevel,
    estimatedAffectedPopulation,
    evacuationRequired,
    affectedArea,
  };
}

// ─── Overlap detection ────────────────────────────────────────────────────────
async function findOverlappingZone(lat, lng, traceId) {
  console.log(`[${traceId}] findOverlappingZone called`);

  const res = await client.send(
    new QueryCommand({
      TableName: TABLE,
      IndexName: INDEX,
      KeyConditionExpression: "#s = :active",
      ExpressionAttributeNames: { "#s": "status" },
      ExpressionAttributeValues: { ":active": "ACTIVE" },
    })
  );

  const found =
    (res.Items ?? []).find((z) => {
      const dLat = Math.abs(z.centerPoint.lat - lat);
      const dLng = Math.abs(z.centerPoint.lng - lng);
      return dLat < 0.12 && dLng < 0.12;
    }) ?? null;

  console.log(
    `[${traceId}] findOverlappingZone result: ${found ? found.id : "none"}`
  );

  return found;
}

// ─── Helper: fetch with timeout ───────────────────────────────────────────────
async function fetchWithTimeout(url, options = {}, timeoutMs = OUTBOUND_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

// ─── Helper: fetch json with retry ────────────────────────────────────────────
async function fetchJsonWithRetry(
  url,
  options = {},
  {
    timeoutMs = OUTBOUND_TIMEOUT_MS,
    maxAttempts = OUTBOUND_MAX_ATTEMPTS,
    serviceName = "ExternalService",
  } = {},
  traceId
) {
  let lastError = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      console.log(
        `[${traceId}] [${serviceName}] Attempt ${attempt}/${maxAttempts} -> ${url}`
      );

      const response = await fetchWithTimeout(url, options, timeoutMs);

      if (!response.ok) {
        lastError = new Error(`[${serviceName}] Response not OK: ${response.status}`);
        console.warn(
          `[${traceId}] [${serviceName}] Attempt ${attempt}/${maxAttempts} failed with status ${response.status}`
        );

        if (attempt === maxAttempts) return null;
        continue;
      }

      const data = await response.json();

      if (attempt > 1) {
        console.log(
          `[${traceId}] [${serviceName}] Success on retry attempt ${attempt}/${maxAttempts}`
        );
      }

      return data;
    } catch (err) {
      lastError = err;

      if (err.name === "AbortError") {
        console.warn(
          `[${traceId}] [${serviceName}] Attempt ${attempt}/${maxAttempts} timed out after ${timeoutMs}ms`
        );
      } else {
        console.warn(
          `[${traceId}] [${serviceName}] Attempt ${attempt}/${maxAttempts} failed: ${err.message}`
        );
      }

      if (attempt === maxAttempts) return null;
    }
  }

  console.warn(
    `[${traceId}] [${serviceName}] All attempts failed: ${lastError?.message ?? "Unknown error"}`
  );
  return null;
}

// ─── Incident Reporter call with timeout + retry + fallback ──────────────────
async function fetchIncidentDetails(incidentType, centerPoint, traceId) {
  console.log(`[${traceId}] Calling IncidentReporter`);

  const url = `${INCIDENT_REPORTER_URL}/incidents?status=VERIFIED`;

  const data = await fetchJsonWithRetry(
    url,
    {
      method: "GET",
      headers: { Accept: "application/json" },
    },
    {
      timeoutMs: OUTBOUND_TIMEOUT_MS,
      maxAttempts: OUTBOUND_MAX_ATTEMPTS,
      serviceName: "IncidentReporter",
    },
    traceId
  );

  if (!data) {
    console.warn(`[${traceId}] [IncidentReporter] Fallback to local input.`);
    return null;
  }

  const items = data.items ?? [];

  const matched = items.find((incident) => {
    const upstreamType = incident.incident_type?.toLowerCase();
    const coords = incident.location?.coordinates;

    if (!coords || coords.length < 2) return false;
    if (upstreamType !== incidentType.toLowerCase()) return false;

    const lng = coords[0];
    const lat = coords[1];

    const dLat = Math.abs(lat - centerPoint.lat);
    const dLng = Math.abs(lng - centerPoint.lng);

    return dLat < 0.05 && dLng < 0.05;
  });

  if (!matched) {
    console.warn(
      `[${traceId}] [IncidentReporter] No matching verified incident found. Fallback to local input.`
    );
    return null;
  }

  console.log(
    `[${traceId}] [IncidentReporter] Matched incident: ${matched.incident_id}`
  );

  return matched;
}

// ════════════════════════════════════════════════════════
// API 1 — GET /impact-zones/active
// ════════════════════════════════════════════════════════
async function getActiveZones(event, traceId) {
  console.log(`[${traceId}] getActiveZones called`);

  const rawSeverity = event.queryStringParameters?.severityLevel;
  const severityLevel = rawSeverity ? rawSeverity.toUpperCase() : undefined;

  const validSev = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  if (severityLevel && !validSev.includes(severityLevel)) {
    return jsonResponse(
      400,
      {
        error: "Bad Request",
        message: "severityLevel ไม่ถูกต้อง",
      },
      traceId
    );
  }

  let keyCondition = "#s = :active";
  const exprNames = { "#s": "status" };
  const exprValues = { ":active": "ACTIVE" };

  if (severityLevel) {
    keyCondition += " AND severityLevel = :sev";
    exprValues[":sev"] = severityLevel;
  }

  const res = await client.send(
    new QueryCommand({
      TableName: TABLE,
      IndexName: INDEX,
      KeyConditionExpression: keyCondition,
      ExpressionAttributeNames: exprNames,
      ExpressionAttributeValues: exprValues,
    })
  );

  return jsonResponse(200, { items: res.Items ?? [] }, traceId);
}

// ════════════════════════════════════════════════════════
// API 1.1 — GET /impact-zones
// ════════════════════════════════════════════════════════
async function getAllZones(event, traceId) {
  console.log(`[${traceId}] getAllZones called`);

  const rawSeverity = event.queryStringParameters?.severityLevel;
  const severityLevel = rawSeverity ? rawSeverity.toUpperCase() : undefined;

  const validSev = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  if (severityLevel && !validSev.includes(severityLevel)) {
    return jsonResponse(
      400,
      {
        error: "Bad Request",
        message: "severityLevel ต้องเป็น CRITICAL | HIGH | MEDIUM | LOW",
      },
      traceId
    );
  }

  const res = await client.send(
    new ScanCommand({
      TableName: TABLE,
      ...(severityLevel
        ? {
            FilterExpression: "severityLevel = :sev",
            ExpressionAttributeValues: {
              ":sev": severityLevel,
            },
          }
        : {}),
    })
  );

  return jsonResponse(200, { items: res.Items ?? [] }, traceId);
}

// ════════════════════════════════════════════════════════
// API 2 — Create GET /impact-zones
// ════════════════════════════════════════════════════════
async function createZone(event, traceId) {
  console.log(`[${traceId}] createZone called`);

  const body = JSON.parse(event.body ?? "{}");
  const { incidentType, centerPoint, reportedTime } = body;

  const validTypes = ["flood", "fire", "earthquake"];
  if (!incidentType || !validTypes.includes(incidentType)) {
    return jsonResponse(400, {
      error: "Bad Request",
      message: "incidentType ไม่ถูกต้อง",
    }, traceId);
  }

  if (!reportedTime) {
    return jsonResponse(400, {
      error: "Bad Request",
      message: "reportedTime จำเป็นต้องมี",
    }, traceId);
  }

  const incidentDetails = await fetchIncidentDetails(
    incidentType,
    centerPoint,
    traceId
  );

  const resolvedIncidentType =
    incidentDetails?.incident_type?.toLowerCase() ?? incidentType;

  const resolvedCenterPoint = incidentDetails?.location?.coordinates
    ? {
        lat: incidentDetails.location.coordinates[1],
        lng: incidentDetails.location.coordinates[0],
      }
    : centerPoint;

  const resolvedReportedTime =
    incidentDetails?.created_at ?? reportedTime;

  const overlap = await findOverlappingZone(
    resolvedCenterPoint.lat,
    resolvedCenterPoint.lng,
    traceId
  );

  const now = new Date().toISOString();
  const computed = computeFields(
    resolvedIncidentType,
    resolvedCenterPoint
  );

  if (overlap) {
    const merged = {
      ...overlap,
      incidentType: resolvedIncidentType,
      centerPoint: resolvedCenterPoint,
      ...computed,
      lastUpdated: now,
    };

    await client.send(new PutCommand({
      TableName: TABLE,
      Item: merged,
    }));

    return jsonResponse(201, merged, traceId);
  }

  const newZone = {
    id: "zone-" + randomUUID().slice(0, 8),
    incidentType: resolvedIncidentType,
    centerPoint: resolvedCenterPoint,
    reportedTime: resolvedReportedTime,
    lastUpdated: now,
    status: "ACTIVE",
    ...computed,
  };

  await client.send(new PutCommand({
    TableName: TABLE,
    Item: newZone,
  }));

  return jsonResponse(201, newZone, traceId);
}

// ════════════════════════════════════════════════════════
// API 3 — PATCH /impact-zones/{id}/severity
// ════════════════════════════════════════════════════════
async function updateSeverity(event, traceId) {
  console.log(`[${traceId}] updateSeverity called`);

  const id = event.pathParameters?.id;
  const body = JSON.parse(event.body ?? "{}");
  const { severityLevel, status } = body;

  if (!severityLevel && !status) {
    return jsonResponse(
      400,
      {
        error: "Bad Request",
        message: "ต้องส่งมาอย่างน้อย 1 field: severityLevel หรือ status",
      },
      traceId
    );
  }

  const validSev = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const validStatus = ["ACTIVE", "CONTAINED", "RESOLVED", "ARCHIVED"];

  if (severityLevel && !validSev.includes(severityLevel)) {
    return jsonResponse(
      400,
      {
        error: "Bad Request",
        message: "severityLevel ต้องเป็น CRITICAL | HIGH | MEDIUM | LOW",
      },
      traceId
    );
  }

  if (status && !validStatus.includes(status)) {
    return jsonResponse(
      400,
      {
        error: "Bad Request",
        message: "status ต้องเป็น ACTIVE | CONTAINED | RESOLVED | ARCHIVED",
      },
      traceId
    );
  }

  const existing = await client.send(
    new GetCommand({ TableName: TABLE, Key: { id } })
  );

  if (!existing.Item) {
    return jsonResponse(
      404,
      {
        error: "Not Found",
        message: `ไม่พบ zone id: ${id}`,
      },
      traceId
    );
  }

  const zone = existing.Item;

  if (status && !isValidStatusTransition(zone.status, status)) {
    return jsonResponse(
      422,
      {
        error: "Unprocessable Entity",
        message: `ไม่สามารถ downgrade status ได้: ${zone.status} → ${status}`,
        allowedFlow: "ACTIVE → CONTAINED → RESOLVED → ARCHIVED",
      },
      traceId
    );
  }

  const now = new Date().toISOString();
  const newSev = severityLevel ?? zone.severityLevel;
  const newStatus = status ?? zone.status;
  const newEvac = ["CRITICAL", "HIGH"].includes(newSev);

  const prevValues = {
    severityLevel: zone.severityLevel,
    status: zone.status,
    evacuationRequired: zone.evacuationRequired,
  };

  const updated = await client.send(
    new UpdateCommand({
      TableName: TABLE,
      Key: { id },
      UpdateExpression:
        "SET severityLevel = :sev, #st = :status, evacuationRequired = :evac, lastUpdated = :now",
      ExpressionAttributeNames: { "#st": "status" },
      ExpressionAttributeValues: {
        ":sev": newSev,
        ":status": newStatus,
        ":evac": newEvac,
        ":now": now,
      },
      ReturnValues: "ALL_NEW",
    })
  );

  return jsonResponse(
    200,
    {
      ...updated.Attributes,
      changeInfo: {
        previousValues: prevValues,
        updatedValues: {
          severityLevel: newSev,
          status: newStatus,
          evacuationRequired: newEvac,
        },
      },
    },
    traceId
  );
}

// ════════════════════════════════════════════════════════
// API 4 — GET /impact-zones/{id}
// ════════════════════════════════════════════════════════
async function getZoneById(event, traceId) {
  console.log(`[${traceId}] getZoneById called`);

  const id = event.pathParameters?.id;

  if (!id) {
    return jsonResponse(
      400,
      {
        error: "Bad Request",
        message: "ต้องระบุ id ใน path",
      },
      traceId
    );
  }

  const result = await client.send(
    new GetCommand({ TableName: TABLE, Key: { id } })
  );

  if (!result.Item) {
    return jsonResponse(
      404,
      {
        error: "Not Found",
        message: `ไม่พบ zone id: ${id}`,
      },
      traceId
    );
  }

  return jsonResponse(200, result.Item, traceId);
}

//════════════════════════════════════════════════════════
//     Versioning function
// ════════════════════════════════════════════════════════
function normalizePath(path) {
  if (path.startsWith("/v1/")) return path.replace("/v1", "");
  return path;
}

//════════════════════════════════════════════════════════
//     Helper
// ════════════════════════════════════════════════════════

function isSnsEvent(event) {
  return Array.isArray(event?.Records) && event.Records[0]?.EventSource === "aws:sns";
}

async function fetchIncidentById(incidentId, traceId) {
  console.log(`[${traceId}] Fetch incident by id: ${incidentId}`);

  const url = `${INCIDENT_REPORTER_URL}/incidents/${incidentId}`;

  const data = await fetchJsonWithRetry(
    url,
    {
      method: "GET",
      headers: { Accept: "application/json" },
    },
    {
      timeoutMs: OUTBOUND_TIMEOUT_MS,
      maxAttempts: OUTBOUND_MAX_ATTEMPTS,
      serviceName: "IncidentReporter",
    },
    traceId
  );

  if (!data) {
    console.warn(`[${traceId}] [IncidentReporter] Failed to fetch incident by id ${incidentId}`);
    return null;
  }

  return data;
}

async function handleIncidentStatusChanged(message, traceId) {
  console.log(`[${traceId}] handleIncidentStatusChanged called`);
  console.log(`[${traceId}] SNS message:`, JSON.stringify(message));

  const incidentId = message.incident_id ?? message.incidentId;
  const newStatus = (
                    message.new_status ??
                    message.newStatus ??
                    message.status ??
                    ""
    ).toUpperCase();

  if (!incidentId) {
    console.warn(`[${traceId}] Missing incidentId in SNS message`);
    return { ignored: true, reason: "missing incidentId" };
  }

  if (newStatus !== "VERIFIED") {
    console.log(`[${traceId}] Ignore status ${newStatus}`);
    return { ignored: true, reason: `status ${newStatus}` };
  }

  const incident = await fetchIncidentById(incidentId, traceId);

  if (!incident) {
    console.warn(`[${traceId}] Incident not found for id ${incidentId}`);
    return { ignored: true, reason: "incident not found" };
  }

  const incidentType = incident.incident_type?.toLowerCase();
  const coords = incident.location?.coordinates;

  if (!incidentType || !coords || coords.length < 2) {
    console.warn(`[${traceId}] Incident data incomplete`);
    return { ignored: true, reason: "incomplete incident data" };
  }

  const centerPoint = {
    lat: coords[1],
    lng: coords[0],
  };

  const reportedTime = incident.created_at ?? new Date().toISOString();

  const overlap = await findOverlappingZone(centerPoint.lat, centerPoint.lng, traceId);
  const now = new Date().toISOString();
  const computed = computeFields(incidentType, centerPoint);

  if (overlap) {
    const SEV = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    const maxSev =
      SEV[
        Math.max(
          SEV.indexOf(overlap.severityLevel),
          SEV.indexOf(computed.severityLevel)
        )
      ];

    const merged = {
      ...overlap,
      incidentType,
      centerPoint,
      severityLevel: maxSev,
      evacuationRequired: ["CRITICAL", "HIGH"].includes(maxSev),
      reportedTime,
      lastUpdated: now,
      sourceIncidentId: incident.incident_id,
      incidentReporterSnapshot: {
        incidentId: incident.incident_id,
        severity: incident.severity,
        incidentStatus: incident.status,
        addressName: incident.address_name,
        affectedCount: incident.affected_count,
        updatedAt: incident.updated_at,
      },
    };

    await client.send(new PutCommand({ TableName: TABLE, Item: merged }));
    return { created: false, merged: true, zoneId: merged.id };
  }

  const newZone = {
    id: "zone-" + randomUUID().slice(0, 8),
    incidentType,
    centerPoint,
    reportedTime,
    lastUpdated: now,
    status: "ACTIVE",
    ...computed,
    sourceIncidentId: incident.incident_id,
    incidentReporterSnapshot: {
      incidentId: incident.incident_id,
      severity: incident.severity,
      incidentStatus: incident.status,
      addressName: incident.address_name,
      affectedCount: incident.affected_count,
      updatedAt: incident.updated_at,
    },
  };

  await client.send(new PutCommand({ TableName: TABLE, Item: newZone }));
  return { created: true, merged: false, zoneId: newZone.id };
}

// ════════════════════════════════════════════════════════
// Main Handler
// ════════════════════════════════════════════════════════
export const handler = async (event) => {
  const traceId = randomUUID();

  console.log(`[${traceId}] EVENT:`, JSON.stringify(event));

  try {
    if (isSnsEvent(event)) {
      const results = [];

      for (const record of event.Records) {
        let message;

        try {
          message = JSON.parse(record.Sns.Message);
        } catch (e) {
          console.warn(
            `[${traceId}] Invalid SNS message: ${record.Sns.Message}`
          );
          results.push({
            ignored: true,
            reason: "invalid SNS message",
          });
          continue;
        }

        const result = await handleIncidentStatusChanged(message, traceId);
        results.push(result);
      }

      console.log(
        `[${traceId}] SNS processing completed: ${JSON.stringify(results)}`
      );

      return {
        traceId,
        results,
      };
    }

    const method = event.httpMethod ?? event.requestContext?.http?.method;
    const rawPath = event.path ?? event.rawPath ?? "";
    const path = normalizePath(rawPath);

    if (method === "OPTIONS") {
      return {
        statusCode: 200,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Allow-Methods": "GET,POST,PATCH,OPTIONS",
        },
        body: "",
      };
    }

    if (method === "GET" && path.includes("/active")) {
      return await getActiveZones(event, traceId);
    }

    if (method === "GET" && path === "/impact-zones") {
      return await getAllZones(event, traceId);
    }

    if (method === "POST" && path === "/impact-zones") {
      return await createZone(event, traceId);
    }

    if (method === "PATCH" && path.includes("/severity")) {
      return await updateSeverity(event, traceId);
    }

    if (method === "GET" && path.match(/\/impact-zones\/[^/]+$/)) {
      return await getZoneById(event, traceId);
    }

    return jsonResponse(
      404,
      {
        error: "Not Found",
        message: `ไม่พบ route: ${method} ${rawPath}`,
      },
      traceId
    );
  } catch (err) {
    console.error(`[${traceId}] ERROR:`, err);

    return jsonResponse(
      500,
      {
        error: "Internal Server Error",
        message: err.message,
      },
      traceId
    );
  }
};