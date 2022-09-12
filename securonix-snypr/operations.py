""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """


import datetime, json, requests, time, xmltodict
from urllib.parse import parse_qs

from connectors.core.connector import get_logger, ConnectorError

from .const import *

logger = get_logger('securonix-snypr')

error_msgs = {
    'time_out': 'The request timed out while trying to connect to the remote server',
    'ssl_error': 'SSL certificate validation failed',
    '500': 'Invalid Request',
    '400': 'Bad Request'
}

TOKEN_VALIDITY = 365


class Securonix(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        self.server_url = config.get('server_url').strip('/')
        self.username = config.get('username')
        self.password = config.get('password')
        self.tenant = config.get('tenant')
        self.verify_ssl = config.get('verify_ssl')
        self.token = None

    def make_rest_call(self, endpoint, params=None, updated_headers=None, payload=None, method='GET'):
        headers = updated_headers if updated_headers else self.generate_headers()
        service_endpoint = '{0}{1}'.format(self.server_url, endpoint)
        logger.debug('Request URL {}'.format(service_endpoint))
        try:
            data = str(payload) if payload else None
            response = requests.request(method, service_endpoint, data=data, headers=headers, params=params,
                                            verify=self.verify_ssl)
            logger.debug('API Response {}'.format(response.text))
            logger.debug('API Status code  {}'.format(response.status_code))
            if response.ok:
                content_type = response.headers.get('Content-Type')
                if 'application/json' in content_type:
                    json_data = json.loads(response.content.decode('utf-8'))
                    error_status = json_data.get('error')
                    if error_status:
                        error_status = error_status.title()
                        try:
                            if not eval(error_status):
                                return json_data
                        except:
                            return json_data
                        else:
                            raise ConnectorError('{}'.format(json_data.get('errorMessage')))
                    return json_data
                elif 'text/plain' in content_type:
                    try:
                        return json.loads(response.content.decode('utf-8'))
                    except:
                        return response.text
                elif 'application/xml' in content_type:
                    return json.loads(json.dumps(xmltodict.parse(response.content.decode('utf-8'))))
            if error_msgs.get(response.status_code):
                raise ConnectorError('{}'.format(error_msgs[response.status_code]))
            else:
                raise ConnectorError('{}'.format(response.content.decode('utf-8')))
        except requests.exceptions.SSLError as e:
            logger.exception(e)
            raise ConnectorError(error_msgs['ssl_error'])
        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
            raise ConnectorError(error_msgs['time_out'])
        except Exception as e:
            logger.exception(e)
            raise ConnectorError(e)

    def validate_token(self, token):
        headers = {
            'token': token
        }
        resp = self.make_rest_call('/Snypr/ws/token/validate', updated_headers=headers)
        if resp == 'Valid':
            return True

    def generate_headers(self):
        headers = {
            'username': self.username,
            'password': str(self.password),
            'tenant': self.tenant,
            'validity': str(TOKEN_VALIDITY)
        }
        if not self.token:
            self.token = self.make_rest_call('/Snypr/ws/token/generate', updated_headers=headers)
        valid = self.validate_token(self.token)
        if valid:
            headers = {'token': self.token}
            return headers


def build_query_string(params):
    last_seen = params.get('dateunit').lower()
    params['dateunit'] = last_seen
    if last_seen.lower() == 'years':
        params.update({'dateunit': 'days'})
    params.update({'dateunitvalue': LAST_SEEN.get(params.get('dateunitvalue'))})
    query_string = {k: v for k, v in params.items() if v is not None and v != ''}
    return query_string


def list_users(config, params):
    sec = Securonix(config)
    return sec.make_rest_call('/Snypr/ws/list/allUsers')


def list_peer_groups(config, params):
    sec = Securonix(config)
    return sec.make_rest_call('/Snypr/ws/list/peerGroups')


def list_resource_groups(config, params):
    sec = Securonix(config)
    return sec.make_rest_call('/Snypr/ws/list/resourceGroups')


def list_policies(config, params):
    sec = Securonix(config)
    return sec.make_rest_call('/Snypr/ws/policy/getAllPolicies')


def get_top_threats(config, params):
    sec = Securonix(config)
    query_string = build_query_string(params)
    query_string.update({'offset': 0, 'max': 1000})
    return sec.make_rest_call('/Snypr/ws/sccWidget/getTopThreats', params=query_string)


def get_top_violations(config, params):
    sec = Securonix(config)
    query_string = build_query_string(params)
    query_string.update({'offset': 0, 'max': 1000})
    return sec.make_rest_call('/Snypr/ws/sccWidget/getTopViolations', params=query_string)


def get_top_violators(config, params):
    offset = params.get('offset')
    if not offset:
        params.update({'offset': 0})
    sec = Securonix(config)
    query_string = build_query_string(params)
    return sec.make_rest_call('/Snypr/ws/sccWidget/getTopViolators', params=query_string)


def convert_xmlto_json(events):
    if events:
        for event in events:
            event.update(json.loads(json.dumps(xmltodict.parse(event.get('policies')))))
            event.update(json.loads(json.dumps(xmltodict.parse(event.get('categories')))))
            event.update({'threatmodels': json.loads(json.dumps(xmltodict.parse(event.get('threatmodels'))))})
        return events
    else:
        return []


def get_risk_score(config, params):
    sec = Securonix(config)
    query = params.get('query')
    query_string = 'index=riskscore'
    if query:
        query_string += " and {}".format(query)
    start = params.get('from')
    if start:
        start = datetime.datetime.strptime(start, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%m/%d/%Y %H:%M:%S")
    end = params.get('to')
    if end:
        end = datetime.datetime.strptime(end, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%d/%m/%Y %H:%M:%S")
    params = {'query': query_string, "from": start, "to": end, 'prettyJson': True}
    resp = sec.make_rest_call('/Snypr/ws/spotter/index/search', params=params)
    events = resp.get('events')
    convert_xmlto_json(events)
    return resp


def get_risk_history(config, params):
    sec = Securonix(config)
    query = params.get('query')
    query_string = 'index=riskscorehistory'
    if query:
        query_string += " and {}".format(query)
    start = params.get('from')
    if start:
        start = datetime.datetime.strptime(start, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%m/%d/%Y %H:%M:%S")
    end = params.get('to')
    if end:
        end = datetime.datetime.strptime(end, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%d/%m/%Y %H:%M:%S")
    params = {'query': query_string, "from": start, "to": end}
    resp = sec.make_rest_call('/Snypr/ws/spotter/index/search', params=params)
    events = resp.get('events')
    convert_xmlto_json(events)
    return resp


def query_users(config, params):
    sec = Securonix(config)
    query = params.get('query')
    query_string = "index=users"
    if query:
        query_string += " and {}".format(query)
    params = {'query': query_string}
    return sec.make_rest_call('/Snypr/ws/spotter/index/search', params=params)


def query_violations(config, params):
    sec = Securonix(config)
    query = params.get('query')
    query_string = "index=violation"
    if query:
        query_string += " and {}".format(query)
        params.update({'query': query_string})
    else:
        params.update({'query': query_string})
    start = params.get('generationtime_from')
    if start:
        params['generationtime_from'] = convert_datetime_format(start)
    end = params.get('generationtime_to')
    if end:
        params['generationtime_to'] = convert_datetime_format(end)
    params.update({"searchViolations": True})
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    logger.info("params: {}".format(params))
    resp = sec.make_rest_call('/Snypr/ws/spotter/index/search', params=params)
    if resp:
        str_resp = json.dumps(resp)
        str_resp = str_resp.replace(u'\u0000', '')
        str_resp = str_resp.replace(u'\\u0000', '')
        json_data = json.loads(str_resp)
        return json_data


def query_watchlist(config, params):
    sec = Securonix(config)
    query = params.get('query')
    query_string = "index=watchlist"
    if query:
        query_string += " and {}".format(query)
    params = {'query': query_string}
    return sec.make_rest_call('/Snypr/ws/spotter/index/search', params=params)


def query_tpi(config, params):
    sec = Securonix(config)
    query = params.get('query')
    query_string = "index=tpi"
    if query:
        query_string += " and {}".format(query)
    params = {'query': query_string}
    return sec.make_rest_call('/Snypr/ws/spotter/index/search', params=params)


def convert_datetime_format(_date):
    return datetime.datetime.strptime(_date, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%m/%d/%Y %H:%M:%S")


def generate_query_string(params):
    query = "query={}".format(params.pop('query', {}))
    event_time_from = params.get('eventtime_from')
    if event_time_from:
        query += '&eventtime_from="{}"'.format(convert_datetime_format(event_time_from))
    event_time_to = params.get('eventtime_to')
    if event_time_to:
        query += '&eventtime_to="{}"'.format(convert_datetime_format(event_time_to))
    generation_time_from = params.get('generationtime_from')
    if generation_time_from:
        query += '&generationtime_from="{}"'.format(convert_datetime_format(generation_time_from))
    generation_time_to = params.get('generationtime_to')
    if generation_time_to:
        query += '&generationtime_to="{}"'.format(convert_datetime_format(generation_time_to))
    return query


def custom_query(config, params):
    sec = Securonix(config)
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    query = generate_query_string(params)
    logger.info("query: {}".format(query))
    query_params = parse_qs(query)
    query_string = {k: v[0] for k, v in query_params.items()}
    logger.info("query_string: {}".format(query_string))
    resp = sec.make_rest_call('/Snypr/ws/spotter/index/search', params=query_string)
    if isinstance(resp, str):
        return json.loads(resp)
    else:
        return resp


def create_incident(config, params):
    sec = Securonix(config)
    params.update({"tenantName": sec.tenant})
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    return sec.make_rest_call('/Snypr/ws/incident/actions', params=params, method='POST')


def get_incident_details(config, params):
    sec = Securonix(config)
    params.update({'type': 'metaInfo'})
    return sec.make_rest_call('/Snypr/ws/incident/get', params=params)


def get_incident_status(config, params):
    sec = Securonix(config)
    params.update({'type': 'status'})
    return sec.make_rest_call('/Snypr/ws/incident/get', params=params)


def get_incident_workflow(config, params):
    sec = Securonix(config)
    params.update({'type': 'workflow'})
    return sec.make_rest_call('/Snypr/ws/incident/get', params=params)


def get_possible_action_for_incident(config, params):
    sec = Securonix(config)
    params.update({'type': 'actions'})
    return sec.make_rest_call('/Snypr/ws/incident/get', params=params)


def get_workflows(config, params):
    sec = Securonix(config)
    params.update({'type': 'workflows'})
    return sec.make_rest_call('/Snypr/ws/incident/get', params=params)


def check_task_on_incident(config, params):
    sec = Securonix(config)
    params.update({'type': 'actionInfo'})
    return sec.make_rest_call('/Snypr/ws/incident/get', params=params)


def get_workflow_default_assignee(config, params):
    sec = Securonix(config)
    params.update({'type': 'defaultAssignee'})
    return sec.make_rest_call('/Snypr/ws/incident/get', params=params)


def take_action_on_incident(config, params):
    sec = Securonix(config)
    other_fields = params.pop('other_fields', {})
    if other_fields:
        params.update(other_fields)
    return sec.make_rest_call('/Snypr/ws/incident/actions', params=params, method='POST')


def add_comment(config, params):
    sec = Securonix(config)
    params.update({'actionName': 'comment'})
    return sec.make_rest_call('/Snypr/ws/incident/actions', params=params, method='POST')


def get_epoch(_date):
    try:
        pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
        return int(time.mktime(time.strptime(_date, pattern)))
    except Exception as Err:
        logger.error('get_epoch: Exception occurred [{0}]'.format(str(Err)))
        raise ConnectorError('get_epoch: Exception occurred [{0}]'.format(str(Err)))


def get_millisecond_epoch_time(_date):
    try:
        pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
        return int(time.mktime(time.strptime(_date, pattern))) * 1000
    except Exception as Err:
        logger.error('get_epoch: Exception occurred [{0}]'.format(str(Err)))
        raise ConnectorError('get_epoch: Exception occurred [{0}]'.format(str(Err)))


def list_incidents(config, params):
    sec = Securonix(config)
    params['type'] = 'list'
    params['from'] = get_millisecond_epoch_time(params.get('from'))
    params['to'] = get_millisecond_epoch_time(params.get('to'))
    params['rangeType'] = params.get('rangeType').lower()
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    return sec.make_rest_call('/Snypr/ws/incident/get', params=params)


def get_available_threat_action(config, params):
    sec = Securonix(config)
    params.update({'type': 'threatActions'})
    return sec.make_rest_call('/Snypr/ws/incident/get', params=params)


def _check_health(config):
    sec = Securonix(config)
    headers = sec.generate_headers()
    if headers:
        logger.info('connector available')
        return True


operations = {
    'list_users': list_users,
    'list_peer_groups': list_peer_groups,
    'list_resource_groups': list_resource_groups,
    'list_policies': list_policies,
    'get_top_threats': get_top_threats,
    'get_top_violations': get_top_violations,
    'get_top_violators': get_top_violators,
    'get_risk_score': get_risk_score,
    'get_risk_history': get_risk_history,
    'query_users': query_users,
    'query_violations': query_violations,
    'query_watchlist': query_watchlist,
    'query_tpi': query_tpi,
    'custom_query': custom_query,
    'list_incidents': list_incidents,
    'create_incident': create_incident,
    'get_incident_details': get_incident_details,
    'get_incident_status': get_incident_status,
    'get_incident_workflow': get_incident_workflow,
    'get_possible_action_for_incident': get_possible_action_for_incident,
    'check_task_on_incident': check_task_on_incident,
    'get_workflow_default_assignee': get_workflow_default_assignee,
    'get_workflows': get_workflows,
    'take_action_on_incident': take_action_on_incident,
    'get_available_threat_action': get_available_threat_action,
    'add_comment': add_comment
}


