import { Container, getContainer } from "@cloudflare/containers";
import { env } from "cloudflare:workers";

const GATEWAY_INSTANCE = "gateway";
const CANDIDATE_ADMIN_PATH = "/__milk/candidate-credential";
const CANDIDATE_CHECK_PATH = "/healthz/candidate-credential";
const CANDIDATE_SHA256_HEADER =
  "x-milk-candidate-api-key-sha256";
const CANDIDATE_STATE_HEADER =
  "x-milk-candidate-credential-state";
const CANDIDATE_OPERATION_HEADER = "x-milk-candidate-operation";
const ADMIN_KEY_ENV = "MILK_CARTON_CONTAINER_ADMIN_KEY";
const MAX_ADMIN_KEY_BYTES = 512;
const MAX_CANDIDATE_KEY_BYTES = 4096;

function containerEnvVars(bindings) {
  return {
    MILK_CARTON_CONFIG_JSON: bindings.MILK_CARTON_CONFIG_JSON,
    MILK_CARTON_OPENAI_API_KEY: bindings.MILK_CARTON_OPENAI_API_KEY,
    MILK_CAPTURE_SAMPLING_KEY_HEX:
      bindings.MILK_CAPTURE_SAMPLING_KEY_HEX,
    MILK_CAPTURE_SAMPLING_KEY_VERSION:
      bindings.MILK_CAPTURE_SAMPLING_KEY_VERSION,
    MILK_CAPTURE_STORE_ACCESS_KEY_ID:
      bindings.MILK_CAPTURE_STORE_ACCESS_KEY_ID,
    MILK_CAPTURE_STORE_SECRET_ACCESS_KEY:
      bindings.MILK_CAPTURE_STORE_SECRET_ACCESS_KEY,
    MILK_ROUTE_STORE_ACCESS_KEY_ID: bindings.MILK_ROUTE_STORE_ACCESS_KEY_ID,
    MILK_ROUTE_STORE_SECRET_ACCESS_KEY:
      bindings.MILK_ROUTE_STORE_SECRET_ACCESS_KEY,
    ...(bindings.MILK_CAPTURE_STORE_SESSION_TOKEN === undefined
      ? {}
      : {
          MILK_CAPTURE_STORE_SESSION_TOKEN:
            bindings.MILK_CAPTURE_STORE_SESSION_TOKEN,
        }),
    ...(bindings.MILK_ROUTE_STORE_SESSION_TOKEN === undefined
      ? {}
      : {
          MILK_ROUTE_STORE_SESSION_TOKEN:
            bindings.MILK_ROUTE_STORE_SESSION_TOKEN,
        }),
    ...(bindings.MILK_CARTON_ROUTE_SECRET_HEX === undefined
      ? {}
      : {
          MILK_CARTON_ROUTE_SECRET_HEX:
            bindings.MILK_CARTON_ROUTE_SECRET_HEX,
        }),
    ...(bindings.MILK_CARTON_CANDIDATE_API_KEY === undefined
      ? {}
      : {
          MILK_CARTON_CANDIDATE_API_KEY:
            bindings.MILK_CARTON_CANDIDATE_API_KEY,
        }),
  };
}

function fixedResponse(status, state) {
  return new Response(
    JSON.stringify({
      schema_version: "milk.gateway-candidate-admin-error.v1",
      state,
    }),
    {
      status,
      headers: {
        "cache-control": "no-store",
        "content-type": "application/json",
      },
    },
  );
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

async function validAdminAuthorization(request, bindings) {
  const expected = bindings[ADMIN_KEY_ENV];
  const authorization = request.headers.get("authorization");
  if (
    typeof expected !== "string" ||
    expected.length < 32 ||
    expected.length > MAX_ADMIN_KEY_BYTES ||
    authorization === null ||
    !authorization.startsWith("Bearer ")
  ) {
    return false;
  }
  const supplied = authorization.slice(7);
  if (
    supplied.length < 32 ||
    supplied.length > MAX_ADMIN_KEY_BYTES ||
    !Array.from(supplied).every((value) => {
      const code = value.charCodeAt(0);
      return code >= 33 && code <= 126;
    })
  ) {
    return false;
  }
  const [expectedHash, suppliedHash] = await Promise.all([
    sha256Hex(expected),
    sha256Hex(supplied),
  ]);
  let difference = 0;
  for (let index = 0; index < expectedHash.length; index += 1) {
    difference |= expectedHash.charCodeAt(index) ^ suppliedHash.charCodeAt(index);
  }
  return difference === 0;
}

async function boundCandidateSha256(bindings) {
  const candidate = bindings.MILK_CARTON_CANDIDATE_API_KEY;
  if (candidate === undefined) {
    return null;
  }
  if (
    typeof candidate !== "string" ||
    candidate.length < 1 ||
    candidate.length > MAX_CANDIDATE_KEY_BYTES
  ) {
    throw new Error("candidate credential binding is invalid");
  }
  return sha256Hex(candidate);
}

export class MilkCarton extends Container {
  defaultPort = 8080;
  sleepAfter = "1m";
  envVars = containerEnvVars(env);
  candidateRestartInFlight = false;
  lastCandidateRestartAt = 0;

  async checkCandidateCredential(candidateSha256) {
    const expected = candidateSha256 === null ? "absent" : candidateSha256;
    const checked = await this.containerFetch(
      new Request(`http://container${CANDIDATE_CHECK_PATH}`, {
        headers: { [CANDIDATE_SHA256_HEADER]: expected },
        method: "GET",
      }),
      8080,
    );
    const checkedSha256 = checked.headers.get(CANDIDATE_SHA256_HEADER);
    const checkedState = checked.headers.get(CANDIDATE_STATE_HEADER);
    const checkedStatus = checked.status;
    if (checked.body !== null) {
      await checked.body.cancel();
    }
    const wantedState = candidateSha256 === null ? "absent" : "loaded";
    if (
      checkedStatus !== 200 ||
      checkedSha256 !== expected ||
      checkedState !== wantedState
    ) {
      throw new Error("candidate credential live check failed");
    }
    return wantedState;
  }

  async inspectCandidateCredential(expectedSha256) {
    const boundSha256 = await boundCandidateSha256(env);
    if (boundSha256 !== null && boundSha256 !== expectedSha256) {
      throw new Error("candidate credential binding changed");
    }
    const previous = await this.getState();
    if (previous.status !== "healthy") {
      throw new Error("container is not healthy");
    }
    const state = await this.checkCandidateCredential(boundSha256);
    const current = await this.getState();
    if (
      current.status !== "healthy" ||
      current.lastChange !== previous.lastChange
    ) {
      throw new Error("container generation changed during inspection");
    }
    return {
      candidate_api_key_sha256: boundSha256,
      container_instance: GATEWAY_INSTANCE,
      container_last_change: current.lastChange,
      schema_version: "milk.gateway-candidate-container-inspection.v1",
      state,
    };
  }

  async restartCandidateCredential(expectedSha256, operation) {
    const now = Date.now();
    if (
      this.candidateRestartInFlight ||
      now - this.lastCandidateRestartAt < 1000
    ) {
      throw new Error("candidate credential restart is rate limited");
    }
    this.candidateRestartInFlight = true;
    this.lastCandidateRestartAt = now;
    try {
      const boundSha256 = await boundCandidateSha256(env);
      const restartSha256 = operation === "install" ? expectedSha256 : boundSha256;
      if (
        (operation === "install" && boundSha256 !== expectedSha256) ||
        (operation === "remove" && boundSha256 !== null) ||
        (operation === "verify" &&
          boundSha256 !== null &&
          boundSha256 !== expectedSha256)
      ) {
        throw new Error("candidate credential binding changed");
      }
      const previous = await this.getState();
      await this.stop();
      let stopped = false;
      for (let attempt = 0; attempt < 80; attempt += 1) {
        const state = await this.getState();
        if (state.status === "stopped" || state.status === "stopped_with_code") {
          stopped = true;
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      if (!stopped) {
        throw new Error("container did not stop");
      }
      await this.startAndWaitForPorts({
        ports: 8080,
        cancellationOptions: {
          instanceGetTimeoutMS: 10000,
          portReadyTimeoutMS: 30000,
          waitInterval: 250,
        },
        startOptions: { envVars: containerEnvVars(env) },
      });
      const wantedState = await this.checkCandidateCredential(restartSha256);
      const current = await this.getState();
      if (
        current.status !== "healthy" ||
        current.lastChange <= previous.lastChange
      ) {
        throw new Error("container generation did not advance");
      }
      return {
        candidate_api_key_sha256: restartSha256,
        container_instance: GATEWAY_INSTANCE,
        container_last_change: current.lastChange,
        previous_container_last_change: previous.lastChange,
        schema_version: "milk.gateway-candidate-container-restart.v1",
        state: wantedState,
      };
    } finally {
      this.candidateRestartInFlight = false;
    }
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === CANDIDATE_CHECK_PATH) {
      return new Response(null, {
        status: 404,
        headers: { "cache-control": "no-store" },
      });
    }
    if (url.pathname === CANDIDATE_ADMIN_PATH && url.search === "") {
      if (request.method !== "POST") {
        return fixedResponse(405, "method_not_allowed");
      }
      if (!(await validAdminAuthorization(request, env))) {
        return fixedResponse(401, "unauthorized");
      }
      const expected = request.headers.get(CANDIDATE_SHA256_HEADER);
      const operation = request.headers.get(CANDIDATE_OPERATION_HEADER);
      if (
        expected === null ||
        !/^[0-9a-f]{64}$/.test(expected) ||
        !["inspect", "install", "remove", "verify"].includes(operation)
      ) {
        return fixedResponse(400, "invalid_expected_sha256");
      }
      const expectedSha256 = expected;
      let boundSha256;
      try {
        boundSha256 = await boundCandidateSha256(env);
      } catch {
        return fixedResponse(503, "binding_invalid");
      }
      if (
        (operation === "install" && boundSha256 !== expectedSha256) ||
        (operation === "remove" && boundSha256 !== null) ||
        (["inspect", "verify"].includes(operation) &&
          boundSha256 !== null &&
          boundSha256 !== expectedSha256)
      ) {
        return fixedResponse(409, "binding_mismatch");
      }
      try {
        const container = getContainer(
          env.MILK_CARTON,
          GATEWAY_INSTANCE,
        );
        const receipt = operation === "inspect"
          ? await container.inspectCandidateCredential(expectedSha256)
          : await container.restartCandidateCredential(expectedSha256, operation);
        return new Response(JSON.stringify(receipt), {
          status: 200,
          headers: {
            "cache-control": "no-store",
            "content-type": "application/json",
          },
        });
      } catch {
        return fixedResponse(
          503,
          operation === "inspect" ? "inspection_failed" : "restart_failed",
        );
      }
    }
    return getContainer(env.MILK_CARTON, GATEWAY_INSTANCE).fetch(
      request,
    );
  },
};
