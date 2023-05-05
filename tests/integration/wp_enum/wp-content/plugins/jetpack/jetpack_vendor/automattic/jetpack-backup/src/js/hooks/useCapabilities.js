import apiFetch from '@wordpress/api-fetch';
import { useEffect, useState } from '@wordpress/element';
import useConnection from './useConnection';

/**
 * Return information and loader of Backup functioality Capabilities
 *
 * @returns {object} capabilities, capabilitiesError, capabilitiesLoaded, fetchCapabilities
 */
export default function useCapabilities() {
	const [ capabilities, setCapabilities ] = useState( null );
	const [ capabilitiesError, setCapabilitiesError ] = useState( null );
	const [ capabilitiesLoaded, setCapabilitiesLoaded ] = useState( false );
	const [ connectionStatus ] = useConnection();

	useEffect( () => {
		const connectionLoaded = 0 < Object.keys( connectionStatus ).length;
		if ( ! connectionLoaded ) {
			return;
		}
		apiFetch( { path: '/jetpack/v4/backup-capabilities' } ).then(
			res => {
				setCapabilities( res.capabilities );
				setCapabilitiesLoaded( true );
			},
			() => {
				setCapabilitiesLoaded( true );
				if ( ! connectionStatus.isUserConnected ) {
					setCapabilitiesError( 'is_unlinked' );
				} else {
					setCapabilitiesError( 'fetch_capabilities_failed' );
				}
			}
		);
	}, [ connectionStatus ] );

	return {
		capabilities,
		capabilitiesError,
		capabilitiesLoaded,
		hasBackupPlan: Array.isArray( capabilities ) && capabilities.includes( 'backup' ),
	};
}
