const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;

const inputFile = 'response.json';
const outputDir = 'outputs';
const outputGroupDir = 'output-group';

//ENUM is here https://github.com/ProtonVPN/python-proton-vpn-api-core/blob/bbb8c535fdd9c4993590ba00a178ccba7366477e/proton/vpn/session/servers/types.py#L37
const P2P = 4;
const STREAMING = 8;
const IPV6 = 16;

const dnsCache = {};

async function resolveDomain(domain) {
  if (dnsCache[domain]) return dnsCache[domain];

  const ipv4 = [];
  const ipv6 = [];
  try {
    const aRecords = await dns.resolve4(domain);
    ipv4.push(...aRecords);
  } catch (_) {}
  try {
    const aaaaRecords = await dns.resolve6(domain);
    ipv6.push(...aaaaRecords);
  } catch (_) {}

  const result = { domain, ipv4, ipv6 };
  dnsCache[domain] = result;
  return result;
}

function getBaseName(name) {
  return name.split('#')[0];
}

function checkIPv6Enabled(domainResult, servers) {
  if (domainResult.ipv6.length > 0) return true;
  for (const s of servers) {
    if (s.ipv6.length > 0) return true;
  }
  return false;
}

function isExcludedCountry(name) {
  return name.startsWith('SE-') || name.startsWith('CH-') || name.startsWith('IS-');
}

function dedupeServers(servers) {
  return [...new Set(servers.map(r => JSON.stringify(r)))].map(r => JSON.parse(r));
}

function extractFeatures(features) {
  return {
    P2P: (features & P2P) !== 0,
    Streaming: (features & STREAMING) !== 0,
  };
}

function sortByCity(entries) {
  return entries.sort((a, b) => {
    const cityA = (a.city || '').toLowerCase();
    const cityB = (b.city || '').toLowerCase();
    if (cityA < cityB) return -1;
    if (cityA > cityB) return 1;
    return 0;
  });
}

function groupByIPv4(allEntries) {
  const map = new Map();

  for (const entry of allEntries) {
    for (const server of entry.Servers) {
      for (const ipv4Addr of server.ipv4) {
        if (!map.has(ipv4Addr)) {
          map.set(ipv4Addr, {
            ipv4: ipv4Addr,
            ipv6: server.ipv6.length > 0 ? server.ipv6[0] : null,
            domain: server.Domain,
            servers: [],
            ipv6Enabled: entry.ipv6Enabled,
            city: entry.City,
            P2P: entry.P2P,
            Streaming: entry.Streaming
          });
        }
        if (map.get(ipv4Addr).servers.indexOf(entry.Name) == -1) map.get(ipv4Addr).servers.push(entry.Name);
      }
    }
  }

  return Array.from(map.values());
}

async function main() {
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir);
  if (!fs.existsSync(outputGroupDir)) fs.mkdirSync(outputGroupDir);

  const rawData = fs.readFileSync(inputFile, 'utf-8');
  const jsonData = JSON.parse(rawData);

  const grouped = {};
  const allEntries = [];

  for (const logical of jsonData.LogicalServers) {
    const baseName = getBaseName(logical.Name);
    if (!grouped[baseName]) {
      grouped[baseName] = [];
    }

    const resolvedDomain = await resolveDomain(logical.Domain);

    const servers = [];
    for (const server of logical.Servers) {
      const resolved = await resolveDomain(server.Domain);
      
      servers.push({
        Domain: resolved.domain,
        ipv4: resolved.ipv4,
        ipv6: resolved.ipv6,
        X25519PublicKey: server.X25519PublicKey,
        EntryIP: server.EntryIP,
        ExitIP: server.ExitIP
      });
    }

    const ipv6Enabled = checkIPv6Enabled(resolvedDomain, servers);
    const entryObj = {
      Name: logical.Name,
      Domain: resolvedDomain,
      City: logical.City || null,
      ipv6Enabled,
      Servers: dedupeServers(servers),
      ...extractFeatures(logical.Features)
    };

    grouped[baseName].push(entryObj);
    if (!isExcludedCountry(entryObj.Name)) allEntries.push(entryObj);
  }

  // Write grouped-by-baseName JSON
  for (const [baseName, data] of Object.entries(grouped)) {
    const outputPath = path.join(outputDir, `${baseName}.json`);
    fs.writeFileSync(outputPath, JSON.stringify(data, null, 2));
    console.log(`Saved: ${outputPath}`);
  }

  // Create grouped-by-IPv4 JSON
  const ipv4Grouped = groupByIPv4(allEntries);
  sortByCity(ipv4Grouped);
  const outputData = {
    genDate: new Date().toISOString(),
    data: ipv4Grouped,
  };

  const outputPathGroup = path.join(outputGroupDir, 'all.json');
  fs.writeFileSync(outputPathGroup, JSON.stringify(outputData, null, 2));
  console.log(`Saved: ${outputPathGroup}`);
}

function _resetDnsCache() {
  for (const key of Object.keys(dnsCache)) {
    delete dnsCache[key];
  }
}

module.exports = { getBaseName, checkIPv6Enabled, groupByIPv4, isExcludedCountry, dedupeServers, extractFeatures, sortByCity, resolveDomain, _resetDnsCache, main, P2P, STREAMING, IPV6 };

if (require.main === module) {
  main().catch((err) => {
    console.error('Error:', err);
  });
}