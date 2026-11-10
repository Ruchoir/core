/**
 * Discovery of an instance. The app starts from a domain: the hub serves the instance's manifest at
 * `https://hub.<domain>/.well-known/ruchoir-manifest` (the file the installer writes), each product
 * describes itself at `/.well-known/ruchoir-product`, and Propolis, the issuer, at
 * `/.well-known/openid-configuration`.
 */

import { secure } from "./encoding.ts";
import type { Fetch } from "./platform.ts";
import { NativeError } from "./errors.ts";

/** What a product says about itself (ADR 0004 of Ruchoir/.github). */
export interface ProductDescription {
  name: string;
  version: string;
  /** The API majors served, each under `/api/<major>/`. */
  api: string[];
  /** The features served: an app decides from these, never from `version`. */
  features: string[];
}

export interface Product {
  /** The name the manifest lists it under: `drive`, `calendar`, `chat`, `hub`. */
  name: string;
  /** Its origin, which is also the `resource` of its access tokens (RFC 8707). */
  url: string;
  /** `null` when the product did not answer: the rest of the instance still works. */
  description: ProductDescription | null;
}

export interface Instance {
  domain: string;
  /** Propolis's origin, the issuer of the instance's tokens. */
  issuer: string;
  /** Every service of the manifest but Propolis. */
  products: Product[];
}

/** The part of Propolis's discovery document the client reads. */
export interface IssuerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  revocation_endpoint?: string;
}

/** The manifest's address for a domain (`example.org`), or the address itself when given one. */
export function manifestUrl(domainOrUrl: string): string {
  if (domainOrUrl.includes("://")) return domainOrUrl;
  return `https://hub.${domainOrUrl.replace(/\/+$/, "")}/.well-known/ruchoir-manifest`;
}

async function getJson(fetch: Fetch, url: string): Promise<Record<string, unknown>> {
  if (!secure(url)) throw new NativeError("discovery", `not a secure address: ${url}`);
  let response;
  try {
    response = await fetch(url, { headers: { accept: "application/json" } });
  } catch (error) {
    throw new NativeError("network", `${url}: ${String(error)}`);
  }
  if (!response.ok) throw new NativeError("discovery", `${url} answered ${response.status}`);
  const body = await response.json().catch(() => null);
  if (!body || typeof body !== "object") throw new NativeError("discovery", `${url}: not a JSON object`);
  return body as Record<string, unknown>;
}

function stripSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

/** The instance a domain or a manifest address names, and the description of each product. */
export async function discoverInstance(fetch: Fetch, domainOrUrl: string): Promise<Instance> {
  const manifest = await getJson(fetch, manifestUrl(domainOrUrl));
  const services = manifest.services as Record<string, { url?: unknown }> | undefined;
  const issuer = services?.propolis?.url;
  if (manifest.version !== 1 || typeof manifest.domain !== "string" || typeof issuer !== "string" || !secure(issuer)) {
    throw new NativeError("discovery", "the manifest is not one this client reads");
  }
  const products = await Promise.all(
    Object.entries(services ?? {})
      .filter(([name, service]) => name !== "propolis" && typeof service?.url === "string" && secure(service.url))
      .map(async ([name, service]): Promise<Product> => {
        const url = stripSlash(service.url as string);
        const description = await getJson(fetch, `${url}/.well-known/ruchoir-product`)
          .then((d) => d as unknown as ProductDescription)
          .catch(() => null);
        return { name, url, description };
      }),
  );
  return { domain: manifest.domain, issuer: stripSlash(issuer), products };
}

/** Propolis's discovery document, which must name `issuer` exactly (OpenID Connect Discovery, 4.3). */
export async function discoverIssuer(fetch: Fetch, issuer: string): Promise<IssuerMetadata> {
  const document = await getJson(fetch, `${stripSlash(issuer)}/.well-known/openid-configuration`);
  if (document.issuer !== issuer) throw new NativeError("discovery", "the discovery document names another issuer");
  const endpoints = ["authorization_endpoint", "token_endpoint", "jwks_uri"] as const;
  for (const name of endpoints) {
    const value = document[name];
    if (typeof value !== "string" || !secure(value)) throw new NativeError("discovery", `${name} is missing`);
  }
  const revocation = document.revocation_endpoint;
  return {
    issuer,
    authorization_endpoint: document.authorization_endpoint as string,
    token_endpoint: document.token_endpoint as string,
    jwks_uri: document.jwks_uri as string,
    revocation_endpoint: typeof revocation === "string" && secure(revocation) ? revocation : undefined,
  };
}
