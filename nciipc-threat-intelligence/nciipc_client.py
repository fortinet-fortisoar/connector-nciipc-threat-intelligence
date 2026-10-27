"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

import requests
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('nciipc-threat-intel')

HEALTH_CHECK_PATH = '/servers/getPyMISPVersion'


class NCIIPCClient(object):
    """
    HTTP client for NCIIPC Threat Intelligence REST API (MISP-based).
    Uses static API Key in Authorization header — no login required.
    """

    def __init__(self, config):
        self.base_url = config.get('serverURL', '').rstrip('/')
        self.api_key = config.get('aPIKey', '').strip()
        self.verify_ssl = config.get('verifySSL', True)

        if not self.base_url:
            raise ConnectorError(
                'Server URL is required. '
                'Example: https://nsac.nciipc.gov.in'
            )
        if not self.api_key:
            raise ConnectorError(
                'API Key is required. '
                'Generate it from your NCIIPC MISP portal: '
                'Profile → My Profile → Auth key.'
            )

        self.session = requests.Session()
        # NCIIPC/MISP uses API Key directly in Authorization header
        # No "Bearer" prefix — just the raw API key
        self.session.headers.update({
            'Authorization': self.api_key,
            'Accept':        'application/json',
            'Content-Type':  'application/json',
        })

    def make_request(self, method, endpoint, data=None, params=None, stream=False):
        """
        Central HTTP request method for all API calls.
        Handles both JSON and raw (CSV/text) responses.
        """
        url = '{0}{1}'.format(self.base_url, endpoint)
        logger.debug('{0} {1}'.format(method.upper(), url))

        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                json=data,
                params=params,
                verify=self.verify_ssl,
                timeout=60,
                stream=stream
            )
            return self._handle_response(response)

        except ConnectorError:
            raise
        except requests.exceptions.SSLError as err:
            logger.error('SSL Error: {0}'.format(str(err)))
            raise ConnectorError(
                'SSL certificate verification failed. '
                'Disable Verify SSL for self-signed certificates. '
                'Error: {0}'.format(str(err))
            )
        except requests.exceptions.ConnectionError as err:
            logger.error('Connection Error: {0}'.format(str(err)))
            raise ConnectorError(
                'Failed to connect to NCIIPC server at {0}. '
                'Verify the Server URL and network/VPN connectivity. '
                'Error: {0}'.format(self.base_url, str(err))
            )
        except requests.exceptions.Timeout:
            logger.error('Request timed out')
            raise ConnectorError(
                'Request timed out after 60 seconds. '
                'The indicator dataset may be large — try reducing the date range.'
            )
        except Exception as err:
            logger.error('Unexpected error: {0}'.format(str(err)))
            raise ConnectorError(
                'Unexpected error during API call: {0}'.format(str(err))
            )

    def _handle_response(self, response):
        """
        Handle HTTP response.
        Returns parsed JSON for json responses.
        Returns raw text for csv/xml/text responses.
        """
        logger.debug('Response status: {0}'.format(response.status_code))

        if response.ok:
            content_type = response.headers.get('Content-Type', '')
            # Return raw text for non-JSON formats (CSV, XML, STIX, text)
            if 'application/json' in content_type or 'json' in content_type:
                try:
                    return {'format': 'json', 'data': response.json()}
                except ValueError:
                    return {'format': 'text', 'data': response.text}
            else:
                return {'format': 'raw', 'data': response.text}

        # Error handling
        error_messages = {
            401: (
                'Unauthorized (401) - API Key is invalid or has been revoked. '
                'Verify the API Key from your NCIIPC MISP portal: '
                'Profile → My Profile → Auth key.'
            ),
            403: (
                'Forbidden (403) - API Key does not have permission for this operation. '
                'Contact your NCIIPC administrator to check your account permissions.'
            ),
            404: (
                'Not Found (404) - The requested endpoint or event does not exist. '
                'Verify the Server URL and endpoint path.'
            ),
            405: (
                'Method Not Allowed (405) - Wrong HTTP method used for this endpoint.'
            ),
            500: (
                'Internal Server Error (500) - An error occurred on the NCIIPC '
                'MISP server. Contact your NCIIPC administrator.'
            ),
        }

        error_msg = error_messages.get(
            response.status_code,
            'HTTP Error {0}'.format(response.status_code)
        )

        try:
            body = response.json()
            if isinstance(body, dict):
                server_detail = (
                    body.get('message')
                    or body.get('errors')
                    or body.get('error')
                    or str(body)
                )
                error_msg += ' | Server message: {0}'.format(server_detail)
        except Exception:
            if response.text:
                error_msg += ' | Response: {0}'.format(response.text[:300])

        logger.error(error_msg)
        raise ConnectorError(error_msg)

    # ------------------------------------------------------------------
    # Convenience wrappers
    # ------------------------------------------------------------------

    def get(self, endpoint, params=None):
        return self.make_request('GET', endpoint, params=params)

    def post(self, endpoint, data):
        return self.make_request('POST', endpoint, data=data)


def get_client(config):
    """Factory: return a configured NCIIPCClient."""
    return NCIIPCClient(config)