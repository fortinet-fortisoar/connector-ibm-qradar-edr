""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json
from requests import request, exceptions as req_exceptions
from datetime import datetime
from connectors.core.connector import get_logger, ConnectorError
from connectors.core.utils import update_connnector_config

logger = get_logger('ibm-security-qradar-edr')


class QRadarEDR:
    def __init__(self, config):
        self.server_url = config.get('server_url', '').strip().strip('/')
        self.secret_key = config.get("secret_key")
        self.app_id = config.get("app_id")
        self.verify_ssl = config.get("verify_ssl")

    def generate_token(self):
        try:
            url = self.server_url + "/rqt-api/1/authenticate"
            data = {
                "secret": self.secret_key,
                "id": self.app_id
            }
            headers = {
                "ContentType": 'application/json'
            }
            response = request("POST", url=url, data=json.dumps(data), headers=headers, verify=self.verify_ssl)
            if response.ok:
                return response.json()
            else:
                logger.error("Error: {0}".format(response.json()))
                raise ConnectorError('{0}:{1}'.format(response.status_code, response.text))
        except req_exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))
        except req_exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))
        except Exception as e:
            logger.error('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))

    def validate_token(self, config, connector_info):
        expires = config['expiresAt']
        if datetime.now().timestamp() > expires:
            logger.info("Token expired at {0}".format(expires))
            token_resp = self.generate_token()
            config['token'] = token_resp.get('token')
            config['expiresAt'] = token_resp.get('expiresAt')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                     config, config['config_id'])
            return config.get('token')
        else:
            logger.info("Token is valid till {0}".format(expires))
            return config.get('token')


def check(config, connector_info):
    try:
        qr = QRadarEDR(config)
        if 'token' in config:
            qr.validate_token(config, connector_info)
            return True
        else:
            token_resp = qr.generate_token()
            config['token'] = token_resp.get('token')
            config['expiresAt'] = token_resp.get('expiresAt')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], config,
                                     config['config_id'])
            return True
    except Exception as err:
        raise ConnectorError(str(err))
