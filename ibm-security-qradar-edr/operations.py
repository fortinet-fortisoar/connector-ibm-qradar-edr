""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError
from .token_generation import *

logger = get_logger('ibm-security-qradar-edr')

TRIGGER_CONDITION = {
    'Code Injection': 0,
    'Process Impersonated': 1,
    'Signature Forged': 2,
    'Incident Correlated': 3,
    'DLL Sideloaded': 4,
    'Suspicious Script Executed': 5,
    'Policies Triggered': 6,
    'Anomalous Behavior Detected': 7,
    'Token Stolen': 8,
    'Ransomware Behavior Detected': 9,
    'Privilege Escalated': 10,
    'External Trigger': 11,
    'Detection Strategy': 12,
    'Antimalware Detection': 13
}


def api_request(method, endpoint, connector_info, config, params=None, data=None):
    try:
        qr = QRadarEDR(config)
        endpoint = qr.server_url + "/rqt-api/1/" + endpoint
        token = qr.validate_token(config, connector_info)
        headers = {
            'ContentType': 'application/json',
            'Authorization': f'Bearer {token}'
        }
        try:
            response = request(method, url=endpoint, headers=headers, params=params, data=data,
                               verify=qr.verify_ssl)
            if response.status_code in [200, 201, 204]:
                return response.json()
            else:
                if response.text != "":
                    err_resp = response.json()
                    failure_msg = err_resp['error']['message']
                    error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                         failure_msg if failure_msg else '')
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))
    except Exception as err:
        raise ConnectorError(str(err))


def make_list_value_params(key, value):
    if key == 'triggerCondition':
        return [TRIGGER_CONDITION.get(x) for x in value]
    if isinstance(value, list):
        return [str(x) for x in value]
    return [x.strip() for x in str(value).split(",")]


def get_alert_list(config, params, connector_info):
    data = {}
    for k, v in params.items():
        if v:
            if k in ['id', 'endpointId', 'triggerCondition', 'tag', 'severity', 'status', 'country', 'gid']:
                data[k] = make_list_value_params(k, v)
            if k in ['severity', 'status']:
                data[k] = [x.lower() for x in data[k]]
            elif k == 'activityState':
                data[k] = v.lower()
            else:
                data[k] = v
    response = api_request("GET", "alerts", connector_info, config, params=data)
    return response


def get_alert_by_id(config, params, connector_info):
    response = api_request("GET", f"alert/{params.get('alert_id')}", connector_info, config)
    return response


def close_alert_by_id(config, params, connector_info):
    response = api_request("POST", f"alert/{params.pop('alert_id')}/close", connector_info, config, params=params)
    return response


def get_alert_by_alert_local_id(config, params, connector_info):
    response = api_request("GET", f"alert/{params.get('alert_local_id')}/endpoint/{params.get('endpoint_id')}",
                           connector_info, config)
    return response


def _check_health(config, connector_info):
    try:
        if check(config, connector_info):
            return True
    except Exception as e:
        logger.error("{0}".format(str(e)))
        raise ConnectorError("{0}".format(str(e)))


operations = {
    'get_alert_list': get_alert_list,
    'get_alert_by_id': get_alert_by_id,
    'close_alert_by_id': close_alert_by_id,
    'get_alert_by_alert_local_id': get_alert_by_alert_local_id
}
