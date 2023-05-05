import { getProductCheckoutUrl } from '@automattic/jetpack-components';
import { Button } from '@wordpress/components';
import { useSelect } from '@wordpress/data';
import { useState, createInterpolateElement, useEffect, useCallback } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import useAnalytics from '../../../hooks/useAnalytics';
import { STORE_ID } from '../../../store';
import Price from './price';
import './style.scss';
import useAddonStorageOffer from './use-addon-storage-offer';
import useStorageStatusText from './use-storage-status-text';

export const StorageAddonUpsellPrompt = ( { usageLevel } ) => {
	const addonSlug = useSelect( select => select( STORE_ID ).getStorageAddonOfferSlug() );
	const { addonSizeText, addonPricing, addOnLoaded } = useAddonStorageOffer();
	const siteSlug = useSelect( select => select( STORE_ID ).getCalypsoSlug() );
	const adminUrl = useSelect( select => select( STORE_ID ).getSiteData().adminUrl );
	const minDaysOfBackupsAllowed = useSelect( select =>
		select( STORE_ID ).getMinDaysOfBackupsAllowed()
	);
	const daysOfBackupsSaved = useSelect( select => select( STORE_ID ).getDaysOfBackupsSaved() );

	const storageStatusText = useStorageStatusText(
		usageLevel,
		daysOfBackupsSaved,
		minDaysOfBackupsAllowed
	);

	const [ pricingText, setPricingText ] = useState( '' );

	const { tracks } = useAnalytics();
	const trackUpgradeStorageClick = useCallback( () => {
		tracks.recordEvent( 'jetpack_backup_upgrade_storage_prompt_cta', { site: siteSlug } );
	}, [ tracks, siteSlug ] );

	useEffect( () => {
		if ( addOnLoaded ) {
			setPricingText(
				createInterpolateElement(
					sprintf(
						// translators: %1$s: Storage unit, <Price>: Additional charge.
						__(
							'Add %1$s additional storage for <Price />/month, billed monthly',
							'jetpack-backup-pkg'
						),
						addonSizeText
					),
					{
						Price: (
							<Price
								fullPrice={ addonPricing.full_price }
								discountPrice={ addonPricing.discount_price }
								currency={ addonPricing.currencyCode }
							/>
						),
					}
				)
			);
		}
	}, [ addonSizeText, addonPricing, addOnLoaded ] );

	const showUpsellPrompt = addOnLoaded;

	return (
		showUpsellPrompt && (
			<Button
				className="usage-warning__action-button has-clickable-action"
				href={ getProductCheckoutUrl(
					addonSlug,
					siteSlug,
					`${ adminUrl }admin.php?page=jetpack-backup`,
					true
				) }
				onClick={ trackUpgradeStorageClick }
			>
				<div className="action-button__copy">
					<div className="action-button__status">{ storageStatusText }</div>
					<div className="action-button__action-text">{ pricingText }</div>
				</div>
				<span className="action-button__arrow">&#8594;</span>
			</Button>
		)
	);
};
