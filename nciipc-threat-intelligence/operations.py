"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

from connectors.core.connector import get_logger, ConnectorError
from .nciipc_client import get_client

logger = get_logger('nciipc-threat-intel')


def _run_operation(config, operation, params):
    """Route operation name to handler."""
    operation_map = {
        'fetch_indicators': fetch_indicators,
        'fetch_attributes': fetch_attributes,
        'get_event_by_id': get_event_by_id

    }
    if operation not in operation_map:
        raise ConnectorError('Unsupported operation: {0}'.format(operation))
    return operation_map[operation](config, params)


# =============================================================================
# HEALTH CHECK
# =============================================================================

def check_health(config):
    """
    Verifies connector health by:
      1. Validating Server URL and API Key are configured.
      2. Calling GET /servers/getPyMISPVersion to confirm:
            - API Key is valid and accepted by NCIIPC MISP server.
            - Server URL is reachable.
            - MISP version info is returned.

    Called automatically by FortiSOAR when:
      - Connector configuration is saved.
      - User clicks Test Connectivity on the connector page.

    Returns True on success, raises ConnectorError on failure.
    """
    logger.info('Running NCIIPC connector health check')

    try:
        client = get_client(config)
        response = client.get('/servers/getPyMISPVersion')

        data = response.get('data', response)
        logger.info(
            'Health check passed. NCIIPC server reachable. '
            'MISP version: {0}'.format(data)
        )
        return True

    except ConnectorError:
        raise
    except Exception as err:
        logger.error('Unexpected error during health check: {0}'.format(str(err)))
        raise ConnectorError(
            'Connector health check failed: {0}'.format(str(err))
        )


# =============================================================================
# OPERATION 1: FETCH INDICATORS
# =============================================================================

def fetch_indicators(config, params):  
    logger.info('Executing fetch_indicators')

    return_format = params.get('returnFormat', 'json').lower()
    date = params.get('date', '1d')
    published = params.get('published', '1')

    # Validate return format
    valid_formats = ['json', 'csv', 'xml']
    if return_format not in valid_formats:
        raise ConnectorError(
            'Invalid return_format: {0}. '
            'Allowed values: {1}'.format(return_format, valid_formats)
        )

    # Build request body — mirrors original curl payload
    body = {
        'returnFormat': return_format,
        'published':    str(published),
    }

    if date:
        body['date'] = date

    client = get_client(config)
    try:
        response = client.post('/events/restSearch', body)

        # Log summary based on format
        if return_format == 'json':
            data = response.get('data', {})
            event_list = data.get('response', []) if isinstance(data, dict) else []
            logger.info(
                'fetch_indicators: returned {0} event(s)'.format(len(event_list))
            )
        else:
            raw_data = response.get('data', '')
            logger.info(
                'fetch_indicators: returned {0} bytes of {1} data'.format(
                    len(str(raw_data)), return_format.upper()
                )
            )

        return response

    except ConnectorError:
        raise
    except Exception as err:
        raise ConnectorError('fetch_indicators failed: {0}'.format(str(err)))


def fetch_attributes(config, params):
    """
    Fetches specific IOC attributes from NCIIPC MISP using attribute-level search.
    More granular than fetch_indicators — returns individual IOC entries.
    """
    logger.info('Executing fetch_attributes')

    return_format = params.get('returnFormat', 'json').lower()
    date = params.get('dateRange', '1d')
    value = params.get('value', '')
    published = params.get('published', '1')

    # Build request body
    body = {
        'returnFormat': return_format,
        'published':    str(published),
    }

    if date:
        body['date'] = date
    if value:
        body['value'] = value

    logger.debug('fetch_attributes: body_keys={0}'.format(list(body.keys())))

    client = get_client(config)
    try:
        response = client.post('/attributes/restSearch', body)

        if return_format == 'json':
            data = response.get('data', {})
            attr_list = (
                data.get('response', {}).get('Attribute', [])
                if isinstance(data, dict) else []
            )
            logger.info(
                'fetch_attributes: returned {0} attribute(s)'.format(len(attr_list))
            )
        else:
            logger.info(
                'fetch_attributes: returned {0} format data'.format(
                    return_format.upper()
                )
            )

        return response

    except ConnectorError:
        raise
    except Exception as err:
        raise ConnectorError('fetch_attributes failed: {0}'.format(str(err)))


def get_event_by_id(config, params):
    """
    Fetches full details of a single MISP event by its event ID.
    Returns complete event including all attributes and metadata.

    """
    logger.info('Executing get_event_by_id')

    event_id = params.get('eventID', '')

    endpoint = '/events/view/{0}'.format(event_id)
    client = get_client(config)

    try:
        response = client.get(endpoint)
        data = response.get('data', response)

        event_info = data.get('Event', {}) if isinstance(data, dict) else {}
        logger.info(
            'get_event_by_id: retrieved event {0} — '
            'attributes: {1}'.format(
                event_id,
                len(event_info.get('Attribute', []))
            )
        )
        return response

    except ConnectorError:
        raise
    except Exception as err:
        raise ConnectorError(
            'get_event_by_id failed for event_id={0}: {1}'.format(
                event_id, str(err)
            )
        )
