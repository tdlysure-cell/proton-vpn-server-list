const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { getBaseName, checkIPv6Enabled, groupByIPv4, isExcludedCountry, dedupeServers, extractFeatures, sortByCity, P2P, STREAMING, IPV6 } = require('./app');

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
