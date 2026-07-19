const { describe, it, beforeEach, afterEach, mock } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { getBaseName, checkIPv6Enabled, groupByIPv4, isExcludedCountry, dedupeServers, extractFeatures, sortByCity, resolveDomain, _resetDnsCache, main, P2P, STREAMING, IPV6 } = require('./app');

describe('getBaseName', () => {
  it('extracts base name before #', () => {
    assert.equal(getBaseName('US#42'), 'US');
  });

  it('returns full name when no # present', () => {
    assert.equal(getBaseName('US'), 'US');
  });

  it('handles multiple # characters by splitting on first', () => {
    assert.equal(getBaseName('CH-US#1#2'), 'CH-US');
  });

  it('returns empty string for name starting with #', () => {
    assert.equal(getBaseName('#42'), '');
  });

  it('handles empty string', () => {
    assert.equal(getBaseName(''), '');
  });
});

describe('checkIPv6Enabled', () => {
  it('returns true when domain has IPv6 addresses', () => {
    const domainResult = { domain: 'test.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: ['::1'] };
    assert.equal(checkIPv6Enabled(domainResult, []), true);
  });

  it('returns true when a server has IPv6 addresses', () => {
    const domainResult = { domain: 'test.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [] };
    const servers = [{ ipv6: ['::1'] }, { ipv6: [] }];
    assert.equal(checkIPv6Enabled(domainResult, servers), true);
  });

  it('returns false when neither domain nor servers have IPv6', () => {
    const domainResult = { domain: 'test.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [] };
    const servers = [{ ipv6: [] }];
    assert.equal(checkIPv6Enabled(domainResult, servers), false);
  });

  it('returns false with empty servers array and no domain IPv6', () => {
    const domainResult = { domain: 'test.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [] };
    assert.equal(checkIPv6Enabled(domainResult, []), false);
  });
});

describe('feature flag constants', () => {
  it('P2P equals 4', () => {
    assert.equal(P2P, 4);
  });

  it('STREAMING equals 8', () => {
    assert.equal(STREAMING, 8);
  });

  it('IPV6 equals 16', () => {
    assert.equal(IPV6, 16);
  });

  it('P2P flag detection via bitwise AND', () => {
    const features = 4;
    assert.equal((features & P2P) !== 0, true);
    assert.equal((features & STREAMING) !== 0, false);
  });

  it('STREAMING flag detection via bitwise AND', () => {
    const features = 8;
    assert.equal((features & STREAMING) !== 0, true);
    assert.equal((features & P2P) !== 0, false);
  });

  it('combined P2P+STREAMING flags detected independently', () => {
    const features = P2P | STREAMING;
    assert.equal((features & P2P) !== 0, true);
    assert.equal((features & STREAMING) !== 0, true);
    assert.equal((features & IPV6) !== 0, false);
  });

  it('no features set yields false for all flags', () => {
    const features = 0;
    assert.equal((features & P2P) !== 0, false);
    assert.equal((features & STREAMING) !== 0, false);
    assert.equal((features & IPV6) !== 0, false);
  });
});

describe('groupByIPv4', () => {
  function makeEntry(name, city, ipv4s, ipv6s, p2p, streaming, ipv6Enabled) {
    return {
      Name: name,
      Domain: { domain: name.toLowerCase().replace('#', '-') + '.protonvpn.net', ipv4: ipv4s, ipv6: ipv6s },
      City: city,
      ipv6Enabled,
      Servers: ipv4s.map((ip, i) => ({
        Domain: name.toLowerCase().replace('#', '-') + '.protonvpn.net',
        ipv4: [ip],
        ipv6: i === 0 ? ipv6s : [],
        X25519PublicKey: 'key' + i,
        EntryIP: ip,
        ExitIP: ip
      })),
      P2P: p2p,
      Streaming: streaming
    };
  }

  it('groups entries by IPv4 address', () => {
    const entries = [makeEntry('US#1', 'New York', ['1.2.3.4'], [], false, false, false)];
    const result = groupByIPv4(entries);
    assert.equal(result.length, 1);
    assert.equal(result[0].ipv4, '1.2.3.4');
  });

  it('deduplicates server names for same IPv4', () => {
    const entry1 = { ...makeEntry('US#1', 'New York', ['1.2.3.4'], [], false, false, false) };
    const entry2 = { ...makeEntry('US#2', 'New York', ['1.2.3.4'], [], false, false, false) };
    const result = groupByIPv4([entry1, entry2]);
    const ipEntry = result.find(r => r.ipv4 === '1.2.3.4');
    assert.ok(ipEntry);
    assert.deepEqual(ipEntry.servers, ['US#1', 'US#2']);
  });

  it('does not add duplicate server names', () => {
    const entry = makeEntry('US#1', 'New York', ['1.2.3.4', '1.2.3.4'], [], false, false, false);
    const result = groupByIPv4([entry]);
    const ipEntry = result.find(r => r.ipv4 === '1.2.3.4');
    assert.ok(ipEntry);
    assert.deepEqual(ipEntry.servers, ['US#1']);
  });

  it('picks first IPv6 address from server for grouped entry', () => {
    const entry = makeEntry('US#1', 'New York', ['1.2.3.4'], ['::1', '::2'], false, false, true);
    const result = groupByIPv4([entry]);
    assert.equal(result[0].ipv6, '::1');
  });

  it('sets ipv6 to null when server has no IPv6', () => {
    const entry = makeEntry('US#1', 'New York', ['1.2.3.4'], [], false, false, false);
    const result = groupByIPv4([entry]);
    assert.equal(result[0].ipv6, null);
  });

  it('preserves city, P2P, Streaming, ipv6Enabled from entry', () => {
    const entry = makeEntry('US#1', 'LA', ['5.6.7.8'], ['::1'], true, true, true);
    const result = groupByIPv4([entry]);
    assert.equal(result[0].city, 'LA');
    assert.equal(result[0].P2P, true);
    assert.equal(result[0].Streaming, true);
    assert.equal(result[0].ipv6Enabled, true);
  });

  it('handles entry with multiple servers on different IPv4s', () => {
    const entry = {
      Name: 'US#1',
      Domain: { domain: 'us-1.protonvpn.net', ipv4: [], ipv6: [] },
      City: 'NYC',
      ipv6Enabled: false,
      Servers: [
        { Domain: 's1.protonvpn.net', ipv4: ['10.0.0.1'], ipv6: [], X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' },
        { Domain: 's2.protonvpn.net', ipv4: ['10.0.0.2'], ipv6: [], X25519PublicKey: 'k2', EntryIP: '10.0.0.2', ExitIP: '10.0.0.2' }
      ],
      P2P: false,
      Streaming: false
    };
    const result = groupByIPv4([entry]);
    assert.equal(result.length, 2);
    assert.equal(result[0].ipv4, '10.0.0.1');
    assert.equal(result[1].ipv4, '10.0.0.2');
  });

  it('returns empty array for empty input', () => {
    const result = groupByIPv4([]);
    assert.deepEqual(result, []);
  });

  it('keeps metadata from first entry when IPv4 is shared across entries', () => {
    const entry1 = {
      Name: 'US#1',
      Domain: { domain: 'us-1.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [] },
      City: 'New York',
      ipv6Enabled: false,
      Servers: [{ Domain: 'us-1.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [], X25519PublicKey: 'k1', EntryIP: '1.2.3.4', ExitIP: '1.2.3.4' }],
      P2P: true,
      Streaming: false
    };
    const entry2 = {
      Name: 'US#2',
      Domain: { domain: 'us-2.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [] },
      City: 'Los Angeles',
      ipv6Enabled: true,
      Servers: [{ Domain: 'us-2.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: ['::1'], X25519PublicKey: 'k2', EntryIP: '1.2.3.4', ExitIP: '1.2.3.4' }],
      P2P: false,
      Streaming: true
    };
    const result = groupByIPv4([entry1, entry2]);
    assert.equal(result.length, 1);
    // First entry's metadata wins for the shared IP
    assert.equal(result[0].city, 'New York');
    assert.equal(result[0].P2P, true);
    assert.equal(result[0].Streaming, false);
    assert.equal(result[0].ipv6Enabled, false);
    // But both server names are collected
    assert.deepEqual(result[0].servers, ['US#1', 'US#2']);
    // First entry's IPv6 (null) wins, even though second has IPv6
    assert.equal(result[0].ipv6, null);
  });

  it('handles entry with server having empty ipv4 array', () => {
    const entry = {
      Name: 'JP#1',
      Domain: { domain: 'jp-1.protonvpn.net', ipv4: [], ipv6: [] },
      City: 'Tokyo',
      ipv6Enabled: false,
      Servers: [{ Domain: 'jp-1.protonvpn.net', ipv4: [], ipv6: [], X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' }],
      P2P: false,
      Streaming: false
    };
    const result = groupByIPv4([entry]);
    assert.equal(result.length, 0);
  });

  it('handles server with multiple IPv4 addresses', () => {
    const entry = {
      Name: 'DE#1',
      Domain: { domain: 'de-1.protonvpn.net', ipv4: [], ipv6: [] },
      City: 'Berlin',
      ipv6Enabled: true,
      Servers: [{ Domain: 'de-1.protonvpn.net', ipv4: ['10.0.0.1', '10.0.0.2'], ipv6: ['::1'], X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' }],
      P2P: false,
      Streaming: false
    };
    const result = groupByIPv4([entry]);
    assert.equal(result.length, 2);
    // Both IPs point to the same server, so name appears in both groups
    assert.deepEqual(result[0].servers, ['DE#1']);
    assert.deepEqual(result[1].servers, ['DE#1']);
    // First IPv6 from the server is used for first IP group
    assert.equal(result[0].ipv6, '::1');
    assert.equal(result[1].ipv6, '::1');
  });

  it('sets domain to the physical server Domain for the grouped IP', () => {
    const entry = {
      Name: 'US#1',
      Domain: { domain: 'us-1.protonvpn.net', ipv4: [], ipv6: [] },
      City: 'New York',
      ipv6Enabled: false,
      Servers: [{ Domain: 'node-us-01.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [], X25519PublicKey: 'k1', EntryIP: '1.2.3.4', ExitIP: '1.2.3.4' }],
      P2P: false,
      Streaming: false
    };
    const result = groupByIPv4([entry]);
    assert.equal(result[0].domain, 'node-us-01.protonvpn.net');
  });

  it('keeps the first server Domain when multiple entries share an IPv4', () => {
    const entry1 = {
      Name: 'US#1',
      Domain: { domain: 'us-1.protonvpn.net', ipv4: [], ipv6: [] },
      City: 'New York',
      ipv6Enabled: false,
      Servers: [{ Domain: 'node-us-01.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [], X25519PublicKey: 'k1', EntryIP: '1.2.3.4', ExitIP: '1.2.3.4' }],
      P2P: false,
      Streaming: false
    };
    const entry2 = {
      Name: 'US#2',
      Domain: { domain: 'us-2.protonvpn.net', ipv4: [], ipv6: [] },
      City: 'New York',
      ipv6Enabled: false,
      Servers: [{ Domain: 'node-us-02.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [], X25519PublicKey: 'k2', EntryIP: '1.2.3.4', ExitIP: '1.2.3.4' }],
      P2P: false,
      Streaming: false
    };
    const result = groupByIPv4([entry1, entry2]);
    assert.equal(result.length, 1);
    // First-entry metadata wins for the shared IP, including the domain
    assert.equal(result[0].domain, 'node-us-01.protonvpn.net');
  });
});

describe('isExcludedCountry', () => {
  it('excludes SE- prefix (Secure Core Sweden)', () => {
    assert.equal(isExcludedCountry('SE-US#1'), true);
  });

  it('excludes CH- prefix (Secure Core Switzerland)', () => {
    assert.equal(isExcludedCountry('CH-US#1'), true);
  });

  it('excludes IS- prefix (Secure Core Iceland)', () => {
    assert.equal(isExcludedCountry('IS-US#1'), true);
  });

  it('does not exclude regular US server', () => {
    assert.equal(isExcludedCountry('US#1'), false);
  });

  it('does not exclude regular JP server', () => {
    assert.equal(isExcludedCountry('JP#1'), false);
  });

  it('does not exclude name that merely contains SE mid-string', () => {
    assert.equal(isExcludedCountry('AUSE#1'), false);
  });

  it('handles empty string', () => {
    assert.equal(isExcludedCountry(''), false);
  });

  it('does not match exact prefix without dash', () => {
    assert.equal(isExcludedCountry('SECURE#1'), false);
  });

  it('does not exclude regular SE/CH/IS-country servers (no dash — not Secure Core multihop)', () => {
    // Only the multi-hop "SE-"/"CH-"/"IS-" prefix is excluded. A plain "SE#1" is a
    // regular Swedish server and must remain in all.json. A regression broadening
    // the check to a bare "SE"/"CH"/"IS" would silently drop every regular server
    // in those countries from the published list.
    assert.equal(isExcludedCountry('SE#1'), false);
    assert.equal(isExcludedCountry('CH#1'), false);
    assert.equal(isExcludedCountry('IS#1'), false);
  });
});

describe('dedupeServers', () => {
  it('removes duplicate server entries', () => {
    const servers = [
      { Domain: 'a.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [], X25519PublicKey: 'k1', EntryIP: '1.2.3.4', ExitIP: '1.2.3.4' },
      { Domain: 'a.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [], X25519PublicKey: 'k1', EntryIP: '1.2.3.4', ExitIP: '1.2.3.4' },
    ];
    const result = dedupeServers(servers);
    assert.equal(result.length, 1);
    assert.deepEqual(result[0], servers[0]);
  });

  it('preserves distinct servers', () => {
    const servers = [
      { Domain: 'a.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [], X25519PublicKey: 'k1', EntryIP: '1.2.3.4', ExitIP: '1.2.3.4' },
      { Domain: 'b.protonvpn.net', ipv4: ['5.6.7.8'], ipv6: ['::1'], X25519PublicKey: 'k2', EntryIP: '5.6.7.8', ExitIP: '5.6.7.8' },
    ];
    const result = dedupeServers(servers);
    assert.equal(result.length, 2);
  });

  it('returns empty array for empty input', () => {
    assert.deepEqual(dedupeServers([]), []);
  });

  it('survives JSON round-trip preserving all properties', () => {
    const server = { Domain: 'a.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: ['::1'], X25519PublicKey: 'k1', EntryIP: '1.2.3.4', ExitIP: '1.2.3.4' };
    const result = dedupeServers([server]);
    assert.equal(result.length, 1);
    assert.equal(result[0].X25519PublicKey, 'k1');
    assert.equal(result[0].EntryIP, '1.2.3.4');
    assert.equal(result[0].ExitIP, '1.2.3.4');
    assert.deepEqual(result[0].ipv4, ['1.2.3.4']);
    assert.deepEqual(result[0].ipv6, ['::1']);
  });

  it('treats servers as duplicates only if all fields match', () => {
    const servers = [
      { Domain: 'a.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [], X25519PublicKey: 'k1', EntryIP: '1.2.3.4', ExitIP: '1.2.3.4' },
      { Domain: 'a.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [], X25519PublicKey: 'k2', EntryIP: '1.2.3.4', ExitIP: '1.2.3.4' },
    ];
    const result = dedupeServers(servers);
    assert.equal(result.length, 2);
  });
});

describe('extractFeatures', () => {
  it('extracts P2P flag when set', () => {
    const result = extractFeatures(P2P);
    assert.equal(result.P2P, true);
    assert.equal(result.Streaming, false);
  });

  it('extracts Streaming flag when set', () => {
    const result = extractFeatures(STREAMING);
    assert.equal(result.P2P, false);
    assert.equal(result.Streaming, true);
  });

  it('extracts both P2P and Streaming when both set', () => {
    const result = extractFeatures(P2P | STREAMING);
    assert.equal(result.P2P, true);
    assert.equal(result.Streaming, true);
  });

  it('returns false for both when features is 0', () => {
    const result = extractFeatures(0);
    assert.equal(result.P2P, false);
    assert.equal(result.Streaming, false);
  });

  it('ignores non-feature bits (e.g. IPV6=16)', () => {
    const result = extractFeatures(IPV6);
    assert.equal(result.P2P, false);
    assert.equal(result.Streaming, false);
  });

  it('handles combined P2P + IPV6 without false Streaming', () => {
    const result = extractFeatures(P2P | IPV6);
    assert.equal(result.P2P, true);
    assert.equal(result.Streaming, false);
  });

  it('returns booleans not numbers', () => {
    const result = extractFeatures(P2P);
    assert.equal(typeof result.P2P, 'boolean');
    assert.equal(typeof result.Streaming, 'boolean');
  });

  it('returns false for both flags when Features is missing/undefined', () => {
    // Defensive data validation: a logical server missing the Features field must
    // not crash or mislabel. (undefined & N) === 0 yields no flags. A refactor
    // that stopped tolerating a missing field would throw on every such entry.
    const result = extractFeatures(undefined);
    assert.equal(result.P2P, false);
    assert.equal(result.Streaming, false);
  });
});

describe('sortByCity', () => {
  it('sorts entries alphabetically by city', () => {
    const entries = [
      { city: 'Zurich', ipv4: '2.2.2.2' },
      { city: 'Amsterdam', ipv4: '1.1.1.1' },
      { city: 'Tokyo', ipv4: '3.3.3.3' },
    ];
    sortByCity(entries);
    assert.equal(entries[0].city, 'Amsterdam');
    assert.equal(entries[1].city, 'Tokyo');
    assert.equal(entries[2].city, 'Zurich');
  });

  it('is case-insensitive', () => {
    const entries = [
      { city: 'zürich', ipv4: '2.2.2.2' },
      { city: 'Amsterdam', ipv4: '1.1.1.1' },
    ];
    sortByCity(entries);
    assert.equal(entries[0].city, 'Amsterdam');
  });

  it('places null cities at the start (empty string sorts first)', () => {
    const entries = [
      { city: 'Tokyo', ipv4: '3.3.3.3' },
      { city: null, ipv4: '1.1.1.1' },
      { city: 'Amsterdam', ipv4: '2.2.2.2' },
    ];
    sortByCity(entries);
    assert.equal(entries[0].city, null);
  });

  it('preserves stable-ish order for equal cities', () => {
    const entries = [
      { city: 'Tokyo', ipv4: '1.1.1.1' },
      { city: 'Tokyo', ipv4: '2.2.2.2' },
    ];
    sortByCity(entries);
    assert.equal(entries[0].ipv4, '1.1.1.1');
    assert.equal(entries[1].ipv4, '2.2.2.2');
  });

  it('handles empty array', () => {
    const entries = [];
    sortByCity(entries);
    assert.deepEqual(entries, []);
  });
});

describe('resolveDomain', () => {
  const dns = require('dns').promises;
  let resolve4Mock;
  let resolve6Mock;

  beforeEach(() => {
    _resetDnsCache();
    resolve4Mock = mock.method(dns, 'resolve4', async () => ['1.2.3.4']);
    resolve6Mock = mock.method(dns, 'resolve6', async () => []);
  });

  afterEach(() => {
    resolve4Mock.mock.restore();
    resolve6Mock.mock.restore();
    _resetDnsCache();
  });

  it('resolves A and AAAA records for a domain', async () => {
    const result = await resolveDomain('test.protonvpn.net');
    assert.equal(result.domain, 'test.protonvpn.net');
    assert.deepEqual(result.ipv4, ['1.2.3.4']);
    assert.deepEqual(result.ipv6, []);
  });

  it('returns cached result on second call without hitting DNS again', async () => {
    await resolveDomain('cached.protonvpn.net');
    await resolveDomain('cached.protonvpn.net');
    assert.equal(resolve4Mock.mock.callCount(), 1);
    assert.equal(resolve6Mock.mock.callCount(), 1);
  });

  it('returns empty ipv4 when A record lookup fails', async () => {
    resolve4Mock.mock.mockImplementation(async () => { throw new Error('ENOTFOUND'); });
    resolve6Mock.mock.mockImplementation(async () => ['::1']);
    const result = await resolveDomain('no-a.protonvpn.net');
    assert.deepEqual(result.ipv4, []);
    assert.deepEqual(result.ipv6, ['::1']);
  });

  it('returns empty ipv6 when AAAA record lookup fails', async () => {
    resolve6Mock.mock.mockImplementation(async () => { throw new Error('ENOTFOUND'); });
    const result = await resolveDomain('no-aaaa.protonvpn.net');
    assert.deepEqual(result.ipv4, ['1.2.3.4']);
    assert.deepEqual(result.ipv6, []);
  });

  it('returns both empty arrays when all DNS lookups fail', async () => {
    resolve4Mock.mock.mockImplementation(async () => { throw new Error('ENOTFOUND'); });
    resolve6Mock.mock.mockImplementation(async () => { throw new Error('ENOTFOUND'); });
    const result = await resolveDomain('no-dns.protonvpn.net');
    assert.deepEqual(result.ipv4, []);
    assert.deepEqual(result.ipv6, []);
    assert.equal(result.domain, 'no-dns.protonvpn.net');
  });

  it('handles multiple A records', async () => {
    resolve4Mock.mock.mockImplementation(async () => ['1.1.1.1', '2.2.2.2']);
    const result = await resolveDomain('multi-a.protonvpn.net');
    assert.deepEqual(result.ipv4, ['1.1.1.1', '2.2.2.2']);
  });
});

describe('main', () => {
  const dns = require('dns').promises;
  const fs = require('fs');
  let resolve4Mock;
  let resolve6Mock;
  let existsSyncMock;
  let mkdirSyncMock;
  let readFileSyncMock;
  let writeFileSyncMock;
  const writtenFiles = {};

  beforeEach(() => {
    _resetDnsCache();
    writtenFiles.files = {};
    resolve4Mock = mock.method(dns, 'resolve4', async (domain) => {
      if (domain.includes('us-')) return ['10.0.0.1'];
      if (domain.includes('ch-')) return ['10.0.0.2'];
      return ['10.0.0.3'];
    });
    resolve6Mock = mock.method(dns, 'resolve6', async () => []);
    existsSyncMock = mock.method(fs, 'existsSync', () => true);
    mkdirSyncMock = mock.method(fs, 'mkdirSync', () => undefined);
    readFileSyncMock = mock.method(fs, 'readFileSync', () => JSON.stringify({
      LogicalServers: [
        {
          Name: 'US#1',
          Domain: 'us-1.protonvpn.net',
          City: 'New York',
          Features: 4,
          Servers: [
            { Domain: 'us-1s.protonvpn.net', X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' }
          ]
        },
        {
          Name: 'JP#1',
          Domain: 'jp-1.protonvpn.net',
          City: 'Tokyo',
          Features: 0,
          Servers: [
            { Domain: 'jp-1s.protonvpn.net', X25519PublicKey: 'k2', EntryIP: '10.0.0.3', ExitIP: '10.0.0.3' }
          ]
        }
      ]
    }));
    writeFileSyncMock = mock.method(fs, 'writeFileSync', (p, content) => {
      writtenFiles.files[p] = content;
    });
  });

  afterEach(() => {
    resolve4Mock.mock.restore();
    resolve6Mock.mock.restore();
    existsSyncMock.mock.restore();
    mkdirSyncMock.mock.restore();
    readFileSyncMock.mock.restore();
    writeFileSyncMock.mock.restore();
    _resetDnsCache();
  });

  it('creates output directories when they do not exist', async () => {
    existsSyncMock.mock.mockImplementation(() => false);
    await main();
    assert.ok(mkdirSyncMock.mock.callCount() >= 2);
  });

  it('skips mkdir when output directories already exist', async () => {
    existsSyncMock.mock.mockImplementation(() => true);
    await main();
    assert.equal(mkdirSyncMock.mock.callCount(), 0);
  });

  it('writes per-baseName JSON files', async () => {
    await main();
    const paths = Object.keys(writtenFiles.files);
    const usPath = paths.find(p => p.includes('US.json'));
    const jpPath = paths.find(p => p.includes('JP.json'));
    assert.ok(usPath, 'US.json should be written');
    assert.ok(jpPath, 'JP.json should be written');
  });

  it('excludes Secure Core entries (SE-, CH-, IS-) from all.json', async () => {
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({
      LogicalServers: [
        {
          Name: 'CH-US#1',
          Domain: 'ch-us-1.protonvpn.net',
          City: 'Zurich',
          Features: 0,
          Servers: [{ Domain: 'ch-us-1s.protonvpn.net', X25519PublicKey: 'k1', EntryIP: '10.0.0.2', ExitIP: '10.0.0.2' }]
        },
        {
          Name: 'US#1',
          Domain: 'us-1.protonvpn.net',
          City: 'New York',
          Features: 0,
          Servers: [{ Domain: 'us-1s.protonvpn.net', X25519PublicKey: 'k2', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' }]
        }
      ]
    }));
    await main();
    const allJsonPath = Object.keys(writtenFiles.files).find(p => p.includes('all.json'));
    assert.ok(allJsonPath);
    const allData = JSON.parse(writtenFiles.files[allJsonPath]);
    const names = allData.data.flatMap(d => d.servers);
    assert.ok(!names.includes('CH-US#1'), 'Secure Core entry should be excluded from all.json');
    assert.ok(names.includes('US#1'), 'Regular entry should be in all.json');
  });

  it('includes genDate in all.json output', async () => {
    await main();
    const allJsonPath = Object.keys(writtenFiles.files).find(p => p.includes('all.json'));
    assert.ok(allJsonPath);
    const allData = JSON.parse(writtenFiles.files[allJsonPath]);
    assert.ok(allData.genDate, 'genDate should be present');
    assert.ok(new Date(allData.genDate).toISOString() === allData.genDate, 'genDate should be valid ISO string');
  });

  it('deduplicates servers within a logical server entry', async () => {
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({
      LogicalServers: [
        {
          Name: 'US#1',
          Domain: 'us-1.protonvpn.net',
          City: 'NYC',
          Features: 0,
          Servers: [
            { Domain: 'us-1s.protonvpn.net', X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' },
            { Domain: 'us-1s.protonvpn.net', X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' }
          ]
        }
      ]
    }));
    await main();
    const usPath = Object.keys(writtenFiles.files).find(p => p.includes('US.json'));
    const usData = JSON.parse(writtenFiles.files[usPath]);
    assert.equal(usData[0].Servers.length, 1);
  });

  it('extracts P2P and Streaming feature flags correctly', async () => {
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({
      LogicalServers: [
        {
          Name: 'US#1',
          Domain: 'us-1.protonvpn.net',
          City: 'NYC',
          Features: 4 | 8,
          Servers: [{ Domain: 'us-1s.protonvpn.net', X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' }]
        }
      ]
    }));
    await main();
    const usPath = Object.keys(writtenFiles.files).find(p => p.includes('US.json'));
    const usData = JSON.parse(writtenFiles.files[usPath]);
    assert.equal(usData[0].P2P, true);
    assert.equal(usData[0].Streaming, true);
  });

  it('sorts all.json data by city', async () => {
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({
      LogicalServers: [
        {
          Name: 'JP#1',
          Domain: 'jp-1.protonvpn.net',
          City: 'Tokyo',
          Features: 0,
          Servers: [{ Domain: 'jp-1s.protonvpn.net', X25519PublicKey: 'k2', EntryIP: '10.0.0.3', ExitIP: '10.0.0.3' }]
        },
        {
          Name: 'US#1',
          Domain: 'us-1.protonvpn.net',
          City: 'Atlanta',
          Features: 0,
          Servers: [{ Domain: 'us-1s.protonvpn.net', X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' }]
        }
      ]
    }));
    await main();
    const allJsonPath = Object.keys(writtenFiles.files).find(p => p.includes('all.json'));
    const allData = JSON.parse(writtenFiles.files[allJsonPath]);
    assert.ok(allData.data.length >= 2);
    assert.equal(allData.data[0].city, 'Atlanta');
    assert.equal(allData.data[1].city, 'Tokyo');
  });

  it('groups multiple servers sharing a baseName into one array file', async () => {
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({
      LogicalServers: [
        {
          Name: 'US#1',
          Domain: 'us-1.protonvpn.net',
          City: 'New York',
          Features: 0,
          Servers: [{ Domain: 'us-1s.protonvpn.net', X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' }]
        },
        {
          Name: 'US#2',
          Domain: 'us-2.protonvpn.net',
          City: 'New York',
          Features: 0,
          Servers: [{ Domain: 'us-2s.protonvpn.net', X25519PublicKey: 'k2', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' }]
        }
      ]
    }));
    await main();
    const usPath = Object.keys(writtenFiles.files).find(p => p.includes('US.json'));
    assert.ok(usPath, 'US.json should be written');
    const usData = JSON.parse(writtenFiles.files[usPath]);
    assert.equal(usData.length, 2, 'US.json should contain both US#1 and US#2');
    assert.deepEqual(usData.map(e => e.Name), ['US#1', 'US#2']);
  });

  it('coerces missing City to null in grouped output', async () => {
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({
      LogicalServers: [
        {
          Name: 'US#1',
          Domain: 'us-1.protonvpn.net',
          Features: 0,
          Servers: [{ Domain: 'us-1s.protonvpn.net', X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' }]
        }
      ]
    }));
    await main();
    const usPath = Object.keys(writtenFiles.files).find(p => p.includes('US.json'));
    const usData = JSON.parse(writtenFiles.files[usPath]);
    assert.equal(usData[0].City, null);
  });

  it('coerces empty-string City to null in grouped output', async () => {
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({
      LogicalServers: [
        {
          Name: 'US#1',
          Domain: 'us-1.protonvpn.net',
          City: '',
          Features: 0,
          Servers: [{ Domain: 'us-1s.protonvpn.net', X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' }]
        }
      ]
    }));
    await main();
    const usPath = Object.keys(writtenFiles.files).find(p => p.includes('US.json'));
    const usData = JSON.parse(writtenFiles.files[usPath]);
    assert.equal(usData[0].City, null);
  });

  it('sets ipv6Enabled true when logical domain resolves an AAAA record', async () => {
    resolve6Mock.mock.mockImplementation(async (domain) => {
      return domain === 'us-1.protonvpn.net' ? ['2001:db8::1'] : [];
    });
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({
      LogicalServers: [
        {
          Name: 'US#1',
          Domain: 'us-1.protonvpn.net',
          City: 'New York',
          Features: 0,
          Servers: [{ Domain: 'us-1s.protonvpn.net', X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' }]
        }
      ]
    }));
    await main();
    const usPath = Object.keys(writtenFiles.files).find(p => p.includes('US.json'));
    const usData = JSON.parse(writtenFiles.files[usPath]);
    assert.equal(usData[0].ipv6Enabled, true);
  });

  it('sets ipv6Enabled true when a physical server resolves an AAAA record', async () => {
    resolve6Mock.mock.mockImplementation(async (domain) => {
      return domain === 'us-1s.protonvpn.net' ? ['2001:db8::2'] : [];
    });
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({
      LogicalServers: [
        {
          Name: 'US#1',
          Domain: 'us-1.protonvpn.net',
          City: 'New York',
          Features: 0,
          Servers: [{ Domain: 'us-1s.protonvpn.net', X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' }]
        }
      ]
    }));
    await main();
    const usPath = Object.keys(writtenFiles.files).find(p => p.includes('US.json'));
    const usData = JSON.parse(writtenFiles.files[usPath]);
    assert.equal(usData[0].ipv6Enabled, true);
    assert.deepEqual(usData[0].Servers[0].ipv6, ['2001:db8::2']);
  });

  it('produces all.json with empty data array when LogicalServers is empty', async () => {
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({ LogicalServers: [] }));
    await main();
    const allJsonPath = Object.keys(writtenFiles.files).find(p => p.includes('all.json'));
    assert.ok(allJsonPath, 'all.json should still be written');
    const allData = JSON.parse(writtenFiles.files[allJsonPath]);
    assert.deepEqual(allData.data, []);
    const baseNameFiles = Object.keys(writtenFiles.files).filter(p => !p.includes('all.json'));
    assert.equal(baseNameFiles.length, 0);
  });

  it('writes entry with empty Servers array when logical server has no physical servers', async () => {
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({
      LogicalServers: [
        {
          Name: 'US#1',
          Domain: 'us-1.protonvpn.net',
          City: 'New York',
          Features: 0,
          Servers: []
        }
      ]
    }));
    await main();
    const usPath = Object.keys(writtenFiles.files).find(p => p.includes('US.json'));
    assert.ok(usPath);
    const usData = JSON.parse(writtenFiles.files[usPath]);
    assert.equal(usData[0].Servers.length, 0, 'entry should have empty Servers array');
    assert.equal(usData[0].ipv6Enabled, false, 'ipv6Enabled should be false with no servers');
    const allJsonPath = Object.keys(writtenFiles.files).find(p => p.includes('all.json'));
    const allData = JSON.parse(writtenFiles.files[allJsonPath]);
    assert.deepEqual(allData.data, [], 'entry with no physical servers should not appear in all.json');
  });

  it('preserves X25519PublicKey, EntryIP, and ExitIP in server output', async () => {
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({
      LogicalServers: [
        {
          Name: 'US#1',
          Domain: 'us-1.protonvpn.net',
          City: 'New York',
          Features: 0,
          Servers: [
            { Domain: 'us-1s.protonvpn.net', X25519PublicKey: 'pubkey123', EntryIP: '10.0.0.1', ExitIP: '10.0.0.2' }
          ]
        }
      ]
    }));
    await main();
    const usPath = Object.keys(writtenFiles.files).find(p => p.includes('US.json'));
    const usData = JSON.parse(writtenFiles.files[usPath]);
    const server = usData[0].Servers[0];
    assert.equal(server.X25519PublicKey, 'pubkey123');
    assert.equal(server.EntryIP, '10.0.0.1');
    assert.equal(server.ExitIP, '10.0.0.2');
    assert.equal(server.Domain, 'us-1s.protonvpn.net');
    assert.deepEqual(server.ipv4, ['10.0.0.1']);
  });

  it('stores resolved domain object (with ipv4/ipv6) as Domain field in output entry', async () => {
    resolve4Mock.mock.mockImplementation(async (domain) => {
      return domain === 'us-1.protonvpn.net' ? ['10.0.0.1'] : ['10.0.0.10'];
    });
    resolve6Mock.mock.mockImplementation(async (domain) => {
      return domain === 'us-1.protonvpn.net' ? ['2001:db8::1'] : [];
    });
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({
      LogicalServers: [
        {
          Name: 'US#1',
          Domain: 'us-1.protonvpn.net',
          City: 'New York',
          Features: 0,
          Servers: [
            { Domain: 'us-1s.protonvpn.net', X25519PublicKey: 'k1', EntryIP: '10.0.0.10', ExitIP: '10.0.0.10' }
          ]
        }
      ]
    }));
    await main();
    const usPath = Object.keys(writtenFiles.files).find(p => p.includes('US.json'));
    const usData = JSON.parse(writtenFiles.files[usPath]);
    assert.equal(usData[0].Domain.domain, 'us-1.protonvpn.net');
    assert.deepEqual(usData[0].Domain.ipv4, ['10.0.0.1']);
    assert.deepEqual(usData[0].Domain.ipv6, ['2001:db8::1']);
    assert.equal(usData[0].ipv6Enabled, true, 'ipv6Enabled should be true when domain has AAAA');
  });

  it('resolves and includes all physical servers when a logical has multiple', async () => {
    resolve4Mock.mock.mockImplementation(async (domain) => {
      if (domain === 'us-1a.protonvpn.net') return ['10.0.0.1'];
      if (domain === 'us-1b.protonvpn.net') return ['10.0.0.2'];
      return ['10.0.0.3'];
    });
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({
      LogicalServers: [
        {
          Name: 'US#1',
          Domain: 'us-1.protonvpn.net',
          City: 'New York',
          Features: 0,
          Servers: [
            { Domain: 'us-1a.protonvpn.net', X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' },
            { Domain: 'us-1b.protonvpn.net', X25519PublicKey: 'k2', EntryIP: '10.0.0.2', ExitIP: '10.0.0.2' }
          ]
        }
      ]
    }));
    await main();
    const usPath = Object.keys(writtenFiles.files).find(p => p.includes('US.json'));
    const usData = JSON.parse(writtenFiles.files[usPath]);
    assert.equal(usData[0].Servers.length, 2, 'both physical servers should be present');
    assert.deepEqual(usData[0].Servers[0].ipv4, ['10.0.0.1']);
    assert.deepEqual(usData[0].Servers[1].ipv4, ['10.0.0.2']);
    assert.equal(usData[0].Servers[0].Domain, 'us-1a.protonvpn.net');
    assert.equal(usData[0].Servers[1].Domain, 'us-1b.protonvpn.net');
    const allJsonPath = Object.keys(writtenFiles.files).find(p => p.includes('all.json'));
    const allData = JSON.parse(writtenFiles.files[allJsonPath]);
    assert.equal(allData.data.length, 2, 'each physical server IP should appear in all.json');
    assert.deepEqual(allData.data[0].servers, ['US#1']);
    assert.deepEqual(allData.data[1].servers, ['US#1']);
  });

  it('writes all.json to the output-group directory (path the S3 workflow depends on)', async () => {
    await main();
    const allJsonPath = Object.keys(writtenFiles.files).find(p => p.includes('all.json'));
    assert.ok(allJsonPath, 'all.json should be written');
    assert.equal(allJsonPath, path.join('output-group', 'all.json'));
  });

  it('writes per-baseName files into the outputs directory', async () => {
    await main();
    const baseNameFiles = Object.keys(writtenFiles.files).filter(p => !p.includes('all.json'));
    assert.ok(baseNameFiles.length > 0, 'per-baseName files should be written');
    for (const p of baseNameFiles) {
      assert.ok(p.startsWith('outputs' + path.sep), `${p} should be inside outputs/`);
    }
  });

  it('rejects when the input file is not valid JSON (errors are not silently swallowed)', async () => {
    readFileSyncMock.mock.mockImplementation(() => 'not-valid-json{');
    await assert.rejects(main(), SyntaxError);
  });

  it('propagates file-read errors (e.g. missing response.json) instead of swallowing them', async () => {
    // Pins the error-propagation contract for a distinct error class from JSON
    // parse failures: a thrown readFileSync (ENOENT etc.) must reach the top-level
    // .catch rather than be silently turned into empty/garbage output.
    readFileSyncMock.mock.mockImplementation(() => {
      throw Object.assign(new Error('ENOENT: no such file or directory'), { code: 'ENOENT' });
    });
    await assert.rejects(main(), (err) => err.code === 'ENOENT');
  });

  it('still writes per-baseName files for Secure Core entries even though they are excluded from all.json', async () => {
    // grouped[baseName].push(entryObj) is UNCONDITIONAL; only allEntries.push()
    // is gated by isExcludedCountry. A regression that moved the grouped push
    // inside the exclusion guard would silently delete every Secure Core
    // per-country file with no signal. Also pins multi-hop baseName grouping:
    // CH-US#1 and CH-US#2 both collapse to baseName "CH-US" and share one file.
    readFileSyncMock.mock.mockImplementation(() => JSON.stringify({
      LogicalServers: [
        {
          Name: 'CH-US#1',
          Domain: 'ch-us-1.protonvpn.net',
          City: 'Zurich',
          Features: 0,
          Servers: [{ Domain: 'ch-us-1s.protonvpn.net', X25519PublicKey: 'k1', EntryIP: '10.0.0.2', ExitIP: '10.0.0.2' }]
        },
        {
          Name: 'CH-US#2',
          Domain: 'ch-us-2.protonvpn.net',
          City: 'Zurich',
          Features: 0,
          Servers: [{ Domain: 'ch-us-2s.protonvpn.net', X25519PublicKey: 'k2', EntryIP: '10.0.0.2', ExitIP: '10.0.0.2' }]
        }
      ]
    }));
    await main();

    const chUsPath = Object.keys(writtenFiles.files).find(p => p === path.join('outputs', 'CH-US.json'));
    assert.ok(chUsPath, 'Secure Core per-baseName file outputs/CH-US.json should still be written');
    const chUsData = JSON.parse(writtenFiles.files[chUsPath]);
    assert.equal(chUsData.length, 2, 'both CH-US#1 and CH-US#2 should be grouped under baseName CH-US');
    assert.deepEqual(chUsData.map(e => e.Name), ['CH-US#1', 'CH-US#2']);

    const allJsonPath = Object.keys(writtenFiles.files).find(p => p.includes('all.json'));
    assert.ok(allJsonPath);
    const allData = JSON.parse(writtenFiles.files[allJsonPath]);
    assert.deepEqual(allData.data, [], 'Secure Core entries must remain excluded from all.json');
  });
});
