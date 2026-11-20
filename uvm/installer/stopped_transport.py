"""Pinned private nested observation transport; never an independent issuer."""
from __future__ import annotations

import base64
import copy
import json
import re

from uvm.installer.offline_artifacts import canonical, pairs
from uvm.installer import route_check

PROFILE = 'volt_stopped_completion_observation_v1'
MAX_TRANSPORT = 262144
MAX_POST = 65536
ZERO_FIELDS = frozenset({'docker_wait_producer_exit', 'docker_wait_filter_exit',
    'routing_tar_producer_exit', 'routing_tar_filter_exit', 'docker_logs_producer_exit',
    'docker_logs_filter_exit', 'post_inspect_producer_exit', 'post_inspect_filter_exit'})
FIELDS = ZERO_FIELDS | {'schema_version', 'profile', 'queried_container_id', 'queried_started_at',
    'docker_wait_stdout_b64', 'routing_tar_b64', 'completion_envelope_b64', 'post_container'}
CONTAINER_FIELDS = {'Name', 'Id', 'Image', 'ImageManifestDescriptor', 'Config', 'HostConfig',
    'NetworkSettings', 'Mounts', 'State'}


def container_shape(item):
    if (type(item)is not dict or set(item)!=CONTAINER_FIELDS
            or type(item['Config'])is not dict or set(item['Config'])!={'Labels'}
            or type(item['Config']['Labels'])is not dict
            or type(item['HostConfig'])is not dict or set(item['HostConfig'])!={'NetworkMode'}
            or type(item['NetworkSettings'])is not dict or set(item['NetworkSettings'])!={'Networks'}
            or type(item['NetworkSettings']['Networks'])is not dict
            or any(type(row)is not dict or set(row)!={'NetworkID','DriverOpts'} for row in item['NetworkSettings']['Networks'].values())
            or type(item['State'])is not dict or set(item['State'])!={'Running','Paused','Restarting','OOMKilled','ExitCode','Error','StartedAt'}
            or type(item['Mounts'])is not list or any(type(m)is not dict or set(m)!={'Type','Name','Source','Destination','Driver','RW'} for m in item['Mounts'])):
        raise ValueError('closed stopped container projection required')
    def text(value, *, nullable=False):
        return value is None if nullable and value is None else type(value)is str
    def string_map(value):
        return type(value)is dict and all(type(k)is str and type(v)is str for k,v in value.items())
    descriptor=item['ImageManifestDescriptor']
    if descriptor is not None:
        if (type(descriptor)is not dict or not {'digest','mediaType','size','platform'}<=set(descriptor)
                or set(descriptor)-{'digest','mediaType','size','platform','annotations','artifactType'}
                or type(descriptor['size'])is not int or descriptor['size']<=0
                or type(descriptor['digest'])is not str or re.fullmatch('sha256:[0-9a-f]{64}',descriptor['digest'])is None
                or type(descriptor['mediaType'])is not str or not string_map(descriptor['platform'])
                or 'annotations'in descriptor and not string_map(descriptor['annotations'])
                or 'artifactType'in descriptor and type(descriptor['artifactType'])is not str):
            raise ValueError('stopped image descriptor types differ')
    state=item['State']
    if (type(item['Name'])is not str or not item['Name'].startswith('/')
            or type(item['Id'])is not str or re.fullmatch('[0-9a-f]{64}',item['Id'])is None
            or type(item['Image'])is not str or re.fullmatch('sha256:[0-9a-f]{64}',item['Image'])is None
            or not string_map(item['Config']['Labels']) or type(item['HostConfig']['NetworkMode'])is not str
            or any(type(name)is not str or type(row['NetworkID'])is not str
                or re.fullmatch('[0-9a-f]{64}',row['NetworkID'])is None
                or row['DriverOpts']is not None and not string_map(row['DriverOpts'])
                for name,row in item['NetworkSettings']['Networks'].items())
            or any(type(state[k])is not bool or state[k]is not False for k in ('Running','Paused','Restarting','OOMKilled'))
            or type(state['ExitCode'])is not int or state['ExitCode']!=0 or type(state['Error'])is not str or state['Error']!=''
            or type(state['StartedAt'])is not str or re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',state['StartedAt'])is None
            or state['StartedAt'].startswith('0001-')
            or any(type(m['Type'])is not str or m['Type']not in ('bind','volume')
                or not text(m['Name'],nullable=True) or type(m['Source'])is not str
                or type(m['Destination'])is not str or not text(m['Driver'],nullable=True)
                or type(m['RW'])is not bool for m in item['Mounts'])):
        raise ValueError('strict stopped scalar and state types differ')
    result=copy.deepcopy(item)
    destinations=[m['Destination']for m in result['Mounts']]
    if any(type(d)is not str for d in destinations)or len(set(destinations))!=len(destinations):
        raise ValueError('stopped projection mount identities are duplicated or malformed')
    result['Mounts'].sort(key=lambda m:m['Destination'])
    return result


def _decode(value, limit):
    if type(value)is not str or len(value)>4*((limit+2)//3):
        raise ValueError('private stopped Base64 bound differs')
    try:raw=base64.b64decode(value,validate=True)
    except (ValueError,TypeError):raise ValueError('private stopped Base64 is malformed')from None
    if not 0<len(raw)<=limit or base64.b64encode(raw).decode()!=value:
        raise ValueError('private stopped Base64 is not canonical or bounded')
    return raw


def decode(raw: str):
    if type(raw)is not str or len(raw.encode('utf-8'))>MAX_TRANSPORT:
        raise ValueError('private stopped transport exceeds its encoded bound')
    value=json.loads(raw,object_pairs_hook=pairs)
    if (type(value)is not dict or set(value)!=FIELDS or type(value['schema_version'])is not int
            or value['schema_version']!=1 or value['profile']!=PROFILE or canonical(value).decode()!=raw
            or any(type(value[k])is not int or value[k]!=0 for k in ZERO_FIELDS)
            or type(value['queried_container_id'])is not str or re.fullmatch('[0-9a-f]{64}',value['queried_container_id'])is None
            or type(value['queried_started_at'])is not str
            or len(canonical(value['post_container']))>MAX_POST):
        raise ValueError('closed current stopped transport or producer outcome differs')
    container_shape(value['post_container'])
    waited=_decode(value['docker_wait_stdout_b64'],2)
    if waited!=b'0\n':raise ValueError('actual current Docker wait is not exact zero')
    return value,_decode(value['routing_tar_b64'],131072),_decode(value['completion_envelope_b64'],2048)


def encode(container, waited, tar, envelope, post, outcomes):
    container_shape(container);container_shape(post)
    if type(outcomes)is not dict or set(outcomes)!=ZERO_FIELDS:
        raise ValueError('every independent stopped producer and reader outcome is required')
    value={'schema_version':1,'profile':PROFILE,'queried_container_id':container['Id'],
        'queried_started_at':container['State']['StartedAt'],'post_container':post,**outcomes}
    for key,raw in (('docker_wait_stdout_b64',waited),('routing_tar_b64',tar),('completion_envelope_b64',envelope)):
        value[key]=base64.b64encode(raw).decode()
    raw=canonical(value).decode();decode(raw)
    return raw


def validate(info, container, raw):
    value,tar,envelope=decode(raw)
    initial=container_shape(container);post=container_shape(value['post_container'])
    if (canonical(initial)!=canonical(post) or value['queried_container_id']!=initial['Id']
            or value['queried_started_at']!=initial['State']['StartedAt']):
        raise ValueError('current stopped acquisition changed CID, StartedAt or projected resources')
    admitted=info['image_admission']
    runtime={'container_id':initial['Id'],'started_at':initial['State']['StartedAt'],
        'image':{'kind':admitted['id_kind'],'id':admitted['id'],'config_id':admitted['image_config_id']},
        'resources_sha256':info['local_start_admission']['resources_sha256']}
    # The caller already freshly validated installation/custody/cache/image and
    # actual stopped resources under its FD. Post data cannot select expectations.
    return route_check.validate_stopped_snapshot(tar,runtime,envelope,0)
