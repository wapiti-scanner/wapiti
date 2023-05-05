import { JetpackVaultPressBackupLogo } from '@automattic/jetpack-components';
import { useSelect } from '@wordpress/data';
import { createInterpolateElement } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { useMemo } from 'react';
import useCapabilities from '../../hooks/useCapabilities';
import useConnection from '../../hooks/useConnection';
import { STORE_ID } from '../../store';
import { useIsFullyConnected } from './hooks';

const Header = () => {
	const showActivateLicenseLink = useShowActivateLicenseLink();

	return (
		<div className="jetpack-admin-page__header">
			<span className="jetpack-admin-page__logo">
				<JetpackVaultPressBackupLogo />
			</span>
			{ showActivateLicenseLink && <ActivateLicenseLink /> }
		</div>
	);
};

const useShowActivateLicenseLink = () => {
	const [ connectionStatus ] = useConnection();
	const isFullyConnected = useIsFullyConnected();
	const { capabilitiesLoaded, hasBackupPlan } = useCapabilities();

	// Give people a chance to activate a license if they're not fully connected,
	// OR if they have a full user connection but no Backup capabilities
	return useMemo( () => {
		// At least wait until we know the status of the site and user connections
		const connectionLoaded = Object.keys( connectionStatus ).length > 0;
		if ( ! connectionLoaded ) {
			return false;
		}

		if ( ! isFullyConnected ) {
			return true;
		}

		// Even if we're fully connected, wait until we know the site's capabilities
		// before deciding to show an activation link
		if ( ! capabilitiesLoaded ) {
			return false;
		}

		return ! hasBackupPlan;
	}, [ connectionStatus, isFullyConnected, hasBackupPlan, capabilitiesLoaded ] );
};

const ActivateLicenseLink = () => {
	const activateLicenseUrl = useSelect( select => {
		const wpAdminUrl = select( STORE_ID ).getSiteData().adminUrl;
		return `${ wpAdminUrl }admin.php?page=my-jetpack#/add-license`;
	}, [] );

	return (
		<p>
			{ createInterpolateElement(
				__(
					'Already have an existing plan or license key? <a>Click here to get started</a>',
					'jetpack-backup-pkg'
				),
				{
					a: <a href={ activateLicenseUrl } />,
				}
			) }
		</p>
	);
};

export default Header;
