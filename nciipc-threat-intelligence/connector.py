"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""
from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import (
    fetch_indicators,
    fetch_attributes,
    get_event_by_id,
    check_health
)

logger = get_logger('nciipc-threat-intel')


class NCIIPCConnector(Connector):

    def execute(self, config, operation, params, **kwargs):
        logger.info('execute() called with operation: {0}'.format(operation))
        try:
            operation_map = {
                'fetch_indicators': fetch_indicators,
                'fetch_attributes': fetch_attributes,
                'get_event_by_id': get_event_by_id
            }
            if operation not in operation_map:
                logger.error('Unsupported operation: {0}'.format(operation))
                raise ConnectorError(
                    'Unsupported operation: {0}'.format(operation)
                )

            result = operation_map[operation](config, params)
            logger.info(
                'Operation {0} completed successfully'.format(operation)
            )
            return result

        except ConnectorError:
            raise
        except Exception as err:
            logger.exception(
                'Unhandled exception in execute(): {0}'.format(str(err))
            )
            raise ConnectorError(str(err))

    def check_health(self, config):
        logger.info('check_health() invoked')
        return check_health(config)
