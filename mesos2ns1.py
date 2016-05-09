#!/usr/bin/env python

import argparse
import sys
import logging
from socket import gethostbyname
from urllib2 import urlopen
import json
import sha
from zbase32 import zbase32
import nsone


# # for testing
# import requests
# requests.packages.urllib3.disable_warnings()


# split a string like 'something@host:port' to get host, port
def pid_to_host_port(pid):
    return pid[pid.find('@')+1:].split(':')


def resolve_v4(host):
    return gethostbyname(host)


def get_task_ips(task, sources, slave_ips):

    def _get_latest_status(task):
        latest = None
        latest_ts = -1.0
        for st in task.get('statuses', []):
            if st['state'] == 'TASK_RUNNING' and st['timestamp'] > latest_ts:
                latest = st
                latest_ts = st['timestamp']
        return latest

    ips = []
    for src in sources:
        if src == 'host':
            slaveip = slave_ips.get(task['slave_id'], None)
            if slaveip is not None:
                ips.append(slaveip)
        elif src == 'netinfo':
            st = _get_latest_status(task)
            netinfos = st.get('container_status', {}).get('network_infos', [])
            for ni in netinfos:
                if 'ip_addresses' in ni and len(ni['ip_addresses']) > 0:
                    for ip in ni['ip_addresses']:
                        ips.append(ip['ip_address'])
                elif 'ip_address' in ni:
                    ips.append(ni['ip_address'])
        elif src == 'mesos':
            st = _get_latest_status(task)
            for lab in st.get('labels', []):
                if lab['key'] == 'MesosContainerizer.NetworkSettings.IPAddress':
                    ips.append(lab['value'])
        elif src == 'docker':
            st = _get_latest_status(task)
            for lab in st.get('labels', []):
                if lab['key'] == 'Docker.NetworkSettings.IPAddress':
                    ips.append(lab['value'])

    return ips


# logic essentially borrowed from mesos-dns
def make_dns_records(state, args):
    R = {}
    slave_ips = {}

    # FIXME: clean up name similar to mesos-dns labels
    def domainify(name):
        return name + '.' + args.zone_name

    def add_rec(domain, rtype, rdata):
        D = domainify(domain)
        if (D, rtype) not in R:
            R[(D, rtype)] = []
        if rdata not in R[(D, rtype)]:
            R[(D, rtype)].append(rdata)

    # create framework records:
    #   frameworkname.domain                   IPs of each framework
    #   _framework._tcp.frameworkname.domain   driver port/IP of each framework
    for fw in state.get('frameworks', []):
        if fw.get('pid', None) is not None:
            host, port = pid_to_host_port(fw['pid'])
        else:
            host, port = fw['hostname'], None
        try:
            addr = resolve_v4(host)
        except:
            logging.debug('framework %s: failed resolving %s so skipping' % (fw['name'], host))
            continue
        add_rec(fw['name'], 'A', [addr])
        if port is not None:
            add_rec('_framework._tcp.' + fw['name'], 'SRV', ['0', '0', port, domainify(fw['name'])])

    # create slave records
    #   slave.domain            IPs of all slaves
    #   _slave._tcp.domain      driver port/IP of all slaves
    for sl in state.get('slaves', []):
        host, port = pid_to_host_port(sl['pid'])
        try:
            addr = resolve_v4(host)
        except:
            logging.debug('slave %s: failed resolving %s' % (sl['id'], host))
            continue
        add_rec('slave', 'A', [addr])
        if port is not None:
            add_rec('_slave._tcp', 'SRV', ['0', '0', port, domainify('slave')])
        slave_ips[sl['id']] = addr

    # create leader records
    host, port = pid_to_host_port(state['leader'])
    leader_addr = None
    try:
        leader_addr = resolve_v4(host)
        add_rec('leader', 'A', [leader_addr])
        add_rec('master', 'A', [leader_addr])
    except:
        logging.debug('leader: failed resolving %s' % host)
    if port is not None:
        add_rec('_leader._tcp', 'SRV', ['0', '0', port, domainify('leader')])
        add_rec('_leader._udp', 'SRV', ['0', '0', port, domainify('leader')])

    # create master records
    msidx = 0
    added_leader_master = False
    for ms in args.mesos_hosts.split(','):
        host, port = ms.split(':')
        try:
            addr = resolve_v4(host)
            if addr == leader_addr:
                added_leader_master = True
            add_rec('master%d' % msidx, 'A', [addr])
            add_rec('master', 'A', [addr])
            msidx += 1
        except:
            logging.debug('master: failed resolving %s' % host)
            continue
    if not added_leader_master:
        add_rec('master%d' % msidx, 'A', [leader_addr])

    # create task records
    for fw in state.get('frameworks', []):
        for tk in fw.get('tasks', []):
            slaveip = slave_ips.get(tk['slave_id'], None)
            ips = get_task_ips(tk, args.task_ip_sources, slave_ips)
            if slaveip is None or len(ips) == 0 or tk['state'] != 'TASK_RUNNING':
                logging.debug('task %s/%s (%s): skipping' % (tk['name'], tk['id'], tk['state']))
                continue
            taskip = ips[0]
            discovery = tk.get('discovery', {})
            name = discovery.get('name', tk.get('name', None))
            idhash = zbase32.b2a(sha.new(tk['id']).digest())[:5]
            slavetail = tk['slave_id'].split('-')[-1].lower()

            arec = '%s.%s' % (name, fw['name'])
            canonical = '%s-%s-%s.%s' % (name, idhash, slavetail, fw['name'])

            add_rec(arec, 'A', [taskip])
            add_rec(canonical, 'A', [taskip])
            add_rec('%s.slave' % arec, 'A', [slaveip])
            add_rec('%s.slave' % canonical, 'A', [slaveip])

            subdomains = ['slave']
            if tk.get('discovery', None) is None:
                subdomains.append(None)
            slave_host = domainify('%s.slave' % canonical)

            rec_names = [
                '_%s._%s.%s%s' % (name, proto, fw['name'], '.%s' % sd if sd else '')
                for proto in ('tcp', 'udp') for sd in subdomains]

            pstring = tk.get('resources', {}).get('ports', None)
            if pstring is None or pstring == '' or pstring == '[]':
                continue
            pstring = pstring[1:-1]  # strip '[' and ']'
            for prange in pstring.split(','):
                plo, phi = prange.split('-')
                for p in range(int(plo), int(phi) + 1):
                    for rec_name in rec_names:
                        add_rec(rec_name, 'SRV', ['0', '0', str(p), slave_host])

            if tk.get('discovery', None) is None:
                break

            for dport in task['discovery'].get('ports', []):
                protos = [dport.get('protocol', None)]
                if protos[0] is None:
                    protos = ['tcp', 'udp']
                rec_names = [
                    '_%s._%s.%s%s' %
                    (name, proto, fw['name'], '.%s' % dport['name'] if 'name' in dport else '')
                    for proto in protos]
                for rec_name in rec_names:
                    add_rec(rec_name, 'SRV', ['0', '0', str(dport['number']), domainify(canonical)])

    return R


def load_mesos_state(mesos_host=None):
    mesos_hosts = args.mesos_hosts.split(',') if mesos_host is None else [mesos_host]
    state = None
    for mh in mesos_hosts:
        url = 'http://%s/master/state.json' % mh
        logging.info('fetching %s' % url)
        try:
            state = json.loads(urlopen(url, timeout=args.mesos_timeout).read())
            break
        except Exception, e:
            logging.warning('failed loading %s: %s' % (url, str(e)))
    return state


if __name__ == '__main__':

    ap = argparse.ArgumentParser(description='Mesos->NS1 DNS management')
    ap.add_argument('-m', '--mesos-hosts', default='127.0.0.1:5050', help='Mesos Master host:port list (comma separated)')
    ap.add_argument('--mesos-timeout', default=10, help='Mesos HTTP timeout', type=int)
    ap.add_argument('--ns1-api-host', default='api.nsone.net', help='NS1 API host')
    ap.add_argument('--ns1-api-port', default=443, help='NS1 API port', type=int)
    ap.add_argument('--ns1-api-timeout', default=10, help='NS1 API timeout', type=int)
    ap.add_argument('-v', '--verbose', action='count', default=0, help='Increase logging level')
    ap.add_argument('-k', '--ns1-api-key', help='NS1 API key', required=True)
    ap.add_argument('-z', '--zone-name', help='DNS zone (e.g. my.mesos)', required=True)
    ap.add_argument('-s', '--task-ip-sources', action='append', choices=['host','netinfo','mesos','docker'], default=['host','netinfo','mesos'], help='Prioritized sources of task IP addresses')
    args = ap.parse_args()

    # set up logging
    loglevels = [logging.WARNING, logging.INFO, logging.DEBUG]
    ll = loglevels[min(len(loglevels) - 1, args.verbose)]
    logging.basicConfig(
        level=ll,
        format='[Mesos->NS1] %(asctime)s %(levelname)s %(message)s')

    # load initial mesos state from any of the configured masters
    state = load_mesos_state()
    if state is None:
        logging.error('failed loading mesos state from any master, bailing')
        sys.exit(1)

    # figure out the leader and load authoritative state from it
    leader_host, leader_port = pid_to_host_port(state['leader'])
    state = load_mesos_state('%s:%s' % (leader_host, leader_port))
    if state is None:
        logging.error('failed loading mesos state from leader, bailing')
        sys.exit(1)

    logging.debug('raw mesos state: %s' % str(state))

    # generate dns records
    cur_recs = make_dns_records(state, args)
    logging.info('%d resulting current records' % len(cur_recs))
    logging.debug(str(cur_recs))

    config = nsone.Config()
    config.createFromAPIKey(args.ns1_api_key)
    ns1 = nsone.NSONE(config=config)

    # get current zone from NS1
    logging.info('pulling current %s zone from NS1' % args.zone_name)
    try:
        zone = ns1.loadZone(args.zone_name)
    except Exception, e:
        logging.error('failed loading %s zone, did you create it in NS1 yet?' % args.zone_name)
        logging.error(str(e))
        sys.exit(1)

    logging.debug('raw records from %s: %s' % (args.zone_name, str(zone.data['records'])))

    # compute records to create, delete, update, and what's unchanged
    existing_recs = {}
    for rec in zone.data['records']:
        k = (rec['domain'], rec['type'])
        v = [a.split(' ') for a in rec['short_answers']]
        existing_recs[k] = v
    existing_keys = set(existing_recs.keys())
    existing_keys -= set([(args.zone_name, 'NS')])  # remove NS rec to avoid messing it up

    cur_keys = set(cur_recs.keys())
    create = cur_keys - existing_keys
    delete = existing_keys - cur_keys
    check = cur_keys & existing_keys
    update = set()
    for k in check:
        if sorted(existing_recs[k]) != sorted(cur_recs[k]):
            logging.debug('CHANGE: %s != %s' % (sorted(existing_recs[k]), sorted(cur_recs[k])))
            update.add(k)
    unchanged = check - update

    logging.debug('create: %s' % str(create))
    logging.debug('delete: %s' % str(delete))
    logging.debug('update: %s' % str(update))
    logging.debug('unchanged: %s' % str(unchanged))

    # render changes to NS1

    call = {'A': zone.add_A, 'SRV': zone.add_SRV}
    for k in create:
        logging.info('creating %s/%s: %s' % (k[0], k[1], cur_recs[k]))
        call[k[1]](k[0], cur_recs[k])

    for k in delete:
        logging.info('deleting %s/%s' % (k[0], k[1]))
        rec = zone.loadRecord(k[0], k[1])
        rec.delete()

    for k in update:
        logging.info('updating %s/%s: %s' % (k[0], k[1], cur_recs[k]))
        rec = zone.loadRecord(k[0], k[1])
        rec.update(answers=cur_recs[k])
