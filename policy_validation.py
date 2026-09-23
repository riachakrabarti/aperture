"""Strict validation for the bounded v2 policy-data format. No activation on error."""
import json


def validate_config(document):
    def need(ok, where):
        if not ok:
            raise ValueError('Invalid policy configuration: ' + where)

    def obj(value, required, optional, where):
        need(isinstance(value, dict), where + ' must be an object')
        need(required <= value.keys() and value.keys() <= required | optional,
             where + ' has missing or unsupported fields')

    def strings(value, where, nonempty=False):
        need(isinstance(value, list) and all(isinstance(x, str) and x for x in value), where)
        need(len(value) == len(set(value)), where + ' has duplicates')
        if nonempty:
            need(bool(value), where + ' is empty')

    obj(document, {'aperture_config'}, set(), 'root')
    c = document['aperture_config']
    obj(c, {'schema_version', 'max_history', 'tools', 'profiles'}, set(), 'config')
    need(type(c['schema_version']) is int and c['schema_version'] == 2, 'schema_version')
    need(type(c['max_history']) is int and 1 <= c['max_history'] <= 500, 'max_history must be 1..500')
    need(isinstance(c['tools'], dict) and bool(c['tools']), 'tools')
    all_tags = set()
    for name, t in c['tools'].items():
        need(isinstance(name, str) and bool(name), 'tool name')
        obj(t, {'description', 'inputSchema', 'tags'}, {'destination_argument', 'spend_argument'}, name)
        need(isinstance(t['description'], str), name + '.description')
        strings(t['tags'], name + '.tags', True)
        all_tags.update(t['tags'])
        s = t['inputSchema']
        obj(s, {'type', 'properties', 'additionalProperties'}, {'required'}, name + '.inputSchema')
        need(s['type'] == 'object' and s['additionalProperties'] is False, name + ' bounded object schema required')
        need(isinstance(s['properties'], dict), name + '.properties')
        strings(s.get('required', []), name + '.required')
        need(set(s.get('required', [])) <= s['properties'].keys(), name + ' required references unknown field')
        for k, spec in s['properties'].items():
            obj(spec, {'type'}, {'minimum', 'maximum'}, name + '.' + k)
            need(spec['type'] in ('string', 'integer'), name + ' unsupported argument type')
            if spec['type'] == 'integer':
                lo, hi = spec.get('minimum', 1), spec.get('maximum', 1000000)
                need(type(lo) is int and type(hi) is int and 1 <= lo <= hi <= 1000000, name + ' integer bounds')
            else:
                need(set(spec) == {'type'}, name + ' unsupported string constraints')
        for tag, field, kind in [('effect:spend', 'spend_argument', 'integer'), ('sink:external', 'destination_argument', 'string')]:
            if tag in t['tags']:
                arg = t.get(field)
                need(isinstance(arg, str) and arg in s.get('required', []) and s['properties'].get(arg, {}).get('type') == kind,
                     name + ' missing or invalid ' + field)
            elif field in t:
                need(False, name + ' metadata without corresponding semantic tag')
    need(isinstance(c['profiles'], dict) and bool(c['profiles']), 'profiles')
    for name, p in c['profiles'].items():
        obj(p, {'label', 'summary', 'extra_tags', 'egress_allowlist', 'max_approval_ttl_seconds', 'sequence_rules', 'evidence', 'deployment_notes'}, set(), 'profile ' + name)
        need(all(isinstance(p[k], str) and p[k] for k in ('label', 'summary')), name + ' labels')
        need(type(p['max_approval_ttl_seconds']) is int and 1 <= p['max_approval_ttl_seconds'] <= 900, name + ' approval TTL')
        strings(p['deployment_notes'], name + '.deployment_notes')
        if p['egress_allowlist'] is not None:
            strings(p['egress_allowlist'], name + '.egress_allowlist')
        need(isinstance(p['extra_tags'], dict), name + '.extra_tags')
        tags = set(all_tags)
        for tool, extra in p['extra_tags'].items():
            need(tool in c['tools'], name + ' extra_tags unknown tool')
            strings(extra, name + '.extra_tags.' + tool)
            # Sensitive semantic tags need matching metadata validated on the base tool.
            need(not (set(extra) - set(c['tools'][tool]['tags'])) & {'effect:spend', 'sink:external'}, name + ' semantic metadata must be on base tool')
            tags.update(extra)
        need(isinstance(p['sequence_rules'], list), name + '.sequence_rules')
        ids = set()
        for r in p['sequence_rules']:
            obj(r, {'id', 'pattern', 'overridable', 'description'}, set(), name + ' rule')
            need(isinstance(r['id'], str) and r['id'] and r['id'] not in ids, name + ' rule id')
            ids.add(r['id'])
            need(type(r['overridable']) is bool and isinstance(r['description'], str), name + ' rule fields')
            need(isinstance(r['pattern'], list) and len(r['pattern']) in (2, 3) and all(isinstance(x, str) and x in tags for x in r['pattern']), name + ' pattern must reference 2 or 3 known tags')
        e = p['evidence']
        obj(e, {'framework', 'baseline', 'by_reason', 'on_approval'}, set(), name + '.evidence')
        need(isinstance(e['framework'], str) and isinstance(e['by_reason'], dict), name + ' evidence fields')
        strings(e['baseline'], name + ' baseline'); strings(e['on_approval'], name + ' on_approval')
        for reason, controls in e['by_reason'].items():
            strings(controls, name + ' reason ' + reason)
    return c


def parse_config(text):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate policy key: ' + key)
            result[key] = value
        return result
    return validate_config(json.loads(text, object_pairs_hook=unique_pairs))
