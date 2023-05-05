import jetpackAnalytics from '@automattic/jetpack-analytics';
import { useConnection } from '@automattic/jetpack-connection';
import { useSelect } from '@wordpress/data';
import { useEffect } from 'react';
import { STORE_ID } from '../store';

const useAnalytics = () => {
	const APINonce = useSelect( select => select( STORE_ID ).getAPINonce(), [] );
	const APIRoot = useSelect( select => select( STORE_ID ).getAPIRoot(), [] );
	const { isUserConnected, userConnectionData = {} } = useConnection( { APIRoot, APINonce } );
	const { login, ID } = userConnectionData.currentUser?.wpcomUser || {};

	/**
	 * Initialize tracks with user data.
	 * Should run when we have a connected user.
	 */
	useEffect( () => {
		if ( ! ( isUserConnected && ID && login ) ) {
			return;
		}

		jetpackAnalytics.initialize( ID, login );
	}, [ ID, isUserConnected, login ] );

	return jetpackAnalytics;
};

export default useAnalytics;
