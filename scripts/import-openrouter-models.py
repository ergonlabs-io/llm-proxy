#!/usr/bin/env python3
"""Import OpenRouter's model catalog into an explicit local llm-proxy config."""
import argparse
from datetime import datetime, timezone
from decimal import Decimal
import getpass
import json
import os
from pathlib import Path
import urllib.request


def billing_entry(entry):
    pricing = entry['pricing']
    # No rounding, inferred cache discounts, or guessed tier thresholds.
    fields = {
        'prompt': 'input_nanodollars_per_token',
        'completion': 'output_nanodollars_per_token',
        'input_cache_read': 'cached_input_nanodollars_per_token',
        'input_cache_write': 'cache_write_nanodollars_per_token',
    }
    tier = {}
    unknown = {}
    for source, target in fields.items():
        if source not in pricing and source in ('input_cache_read', 'input_cache_write'):
            unknown['cached_input_unpriced' if source == 'input_cache_read' else 'cache_write_unpriced'] = True
            tier[target] = 0
            continue
        if source not in pricing:
            return None, f'{source} rate not published; no rate inferred'
        rate = Decimal(pricing[source]) * 1_000_000_000
        if not rate.is_finite() or rate < 0 or rate > 2**64 - 1 or rate != rate.to_integral_value():
            if source in ('input_cache_read', 'input_cache_write'):
                unknown['cached_input_unpriced' if source == 'input_cache_read' else 'cache_write_unpriced'] = True
                tier[target] = 0
                continue
            return None, f'{source} is dynamic or not representable in integer nanodollars'
        tier[target] = int(rate)
    # The proxy's cache-write bucket cannot distinguish cache lifetimes.
    if 'input_cache_write_1h' in pricing and pricing.get('input_cache_write_1h') != pricing.get('input_cache_write'):
        unknown['cache_write_unpriced'] = True
    tiers = [tier]
    thresholds = []
    for override in pricing.get('overrides', []):
        threshold = override.get('min_prompt_tokens')
        if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold <= 0:
            return None, 'invalid tier threshold'
        thresholds.append(threshold)
        merged = {**pricing, **override}
        merged.pop('overrides', None)
        converted, reason = billing_entry({'id': entry['id'], 'pricing': merged})
        if reason:
            return None, 'tier: ' + reason
        tiers.append(converted['tiers'][0])
        for flag in ('cached_input_unpriced', 'cache_write_unpriced'):
            if converted.get(flag): unknown[flag] = True
    if thresholds != sorted(set(thresholds)):
        return None, 'tier thresholds not strictly increasing'
    for previous, threshold in zip(tiers, thresholds):
        previous['up_to'] = threshold - 1
    return {'provider_type': 'openrouter', 'model': entry['id'],
            'tier_mode': 'whole_request', 'tiers': tiers, **unknown}, None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=Path('examples/llmproxy-openrouter.yaml'))
    parser.add_argument('--pricing-out', type=Path, default=Path('examples/openrouter-pricing.json'))
    parser.add_argument('--prompt-key', action='store_true', help='Read the key securely from the terminal')
    args = parser.parse_args()
    key = (None if args.prompt_key else os.environ.get('OPENROUTER_API_KEY')) or getpass.getpass('OpenRouter API key: ')
    request = urllib.request.Request('https://openrouter.ai/api/v1/models', headers={'Authorization': f'Bearer {key}'})
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read(16 * 1024 * 1024 + 1)
    if len(payload) > 16 * 1024 * 1024:
        raise ValueError('model catalog exceeds 16 MiB')
    catalog = json.loads(payload)
    ids = sorted({entry['id'] for entry in catalog['data']})
    if not ids or any(not isinstance(model, str) or not model or '*' in model for model in ids):
        raise ValueError('catalog contains invalid model IDs')
    snapshot = {
        'source': 'https://openrouter.ai/api/v1/models',
        'fetched_at': datetime.now(timezone.utc).isoformat(),
        'models': [{'id': entry['id'], 'pricing': entry['pricing']}
                   for entry in sorted(catalog['data'], key=lambda entry: entry['id'])],
    }
    args.pricing_out.parent.mkdir(parents=True, exist_ok=True)

    entries = []
    for model in snapshot['models']:
        entry, reason = billing_entry(model)
        model['billing_status'] = reason or ('token rates installed; unpriced cache usage remains unknown; non-token charges excluded' if entry.get('cached_input_unpriced') or entry.get('cache_write_unpriced') else 'token rates installed; non-token charges excluded')
        if entry is not None:
            entries.append(entry)
    if not entries:
        raise ValueError('no exact input/output token rate cards available')
    config = {
        'version': 0, 'listen': '127.0.0.1:8080', 'admin': '127.0.0.1:9901',
        'providers': {'openrouter': {'api_key': '${OPENROUTER_API_KEY}'}},
        'routes': [],
        'models': {model: {'providers': [{'provider': 'openrouter', 'model': model}]} for model in ids},
        'pricing': {'catalog': snapshot, 'price_list': {
            'version': 'openrouter-' + snapshot['fetched_at'],
            'effective_from': snapshot['fetched_at'], 'entries': entries}},
        'observability': {'access_logs': {'output': 'stdout', 'format': 'json'}},
    }
    args.pricing_out.write_text(json.dumps(snapshot, indent=2) + '\n')
    print(f'Installed exact token rate cards for {len(entries)} models; other models have explicit unavailable reasons.')
    # JSON is a YAML subset, and preserves model IDs without a YAML dependency.
    args.out.write_text(json.dumps(config, indent=2) + '\n')
    print(f'Saved full pricing snapshot to {args.pricing_out}.')
    print(f'Imported {len(ids)} models into {args.out}; API key is referenced through the environment.')


if __name__ == '__main__':
    main()
