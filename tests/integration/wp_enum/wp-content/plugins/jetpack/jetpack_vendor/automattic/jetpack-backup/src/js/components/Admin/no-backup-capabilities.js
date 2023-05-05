import { Container, Col, getRedirectUrl, PricingCard } from '@automattic/jetpack-components';
import apiFetch from '@wordpress/api-fetch';
import { useSelect } from '@wordpress/data';
import { useState, useEffect, useCallback } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import useAnalytics from '../../hooks/useAnalytics';
import { STORE_ID } from '../../store';

const NoBackupCapabilities = () => {
	const { tracks } = useAnalytics();
	const [ priceAfter, setPriceAfter ] = useState( 0 );
	const [ price, setPrice ] = useState( 0 );
	const [ currencyCode, setCurrencyCode ] = useState( 'USD' );
	const [ introOffer, setIntroOffer ] = useState( null );
	const domain = useSelect( select => select( STORE_ID ).getCalypsoSlug(), [] );

	useEffect( () => {
		apiFetch( { path: '/jetpack/v4/backup-promoted-product-info' } ).then( res => {
			setCurrencyCode( res.currency_code );
			setPrice( res.cost / 12 );

			if ( res.introductory_offer ) {
				setIntroOffer( res.introductory_offer );
				setPriceAfter( res.introductory_offer.cost_per_interval / 12 );
			} else {
				setPriceAfter( res.cost / 12 );
			}
		} );
	}, [] );

	const sendToCart = useCallback( () => {
		tracks.recordEvent( 'jetpack_backup_plugin_upgrade_click', { site: domain } );
		window.location.href = getRedirectUrl( 'backup-plugin-upgrade-10gb', { site: domain } );
	}, [ tracks, domain ] );

	const basicInfoText = __( '14 day money back guarantee.', 'jetpack-backup-pkg' );
	const introductoryInfoText = __(
		'Special introductory pricing, all renewals are at full price. 14 day money back guarantee.',
		'jetpack-backup-pkg'
	);
	const priceDetails =
		introOffer?.interval_unit === 'month' && introOffer?.interval_count === 1
			? sprintf(
					// translators: %s is the regular monthly price
					__( 'trial for the first month, then $%s /month, billed yearly', 'jetpack-backup-pkg' ),
					price
			  )
			: __(
					'per month, billed yearly',
					'jetpack-backup-pkg',
					/* dummy arg to avoid bad minification */ 0
			  );

	return (
		<Container horizontalSpacing={ 3 } horizontalGap={ 3 }>
			<Col lg={ 6 } md={ 6 } sm={ 4 }>
				<h1>{ __( 'Secure your site with a Backup subscription.', 'jetpack-backup-pkg' ) }</h1>
				<p>
					{ ' ' }
					{ __(
						'Get peace of mind knowing that all your work will be saved, and get back online quickly with one-click restores.',
						'jetpack-backup-pkg'
					) }
				</p>
				<ul className="jp-product-promote">
					<li>{ __( 'Automated real-time backups', 'jetpack-backup-pkg' ) }</li>
					<li>{ __( 'Easy one-click restores', 'jetpack-backup-pkg' ) }</li>
					<li>{ __( 'Complete list of all site changes', 'jetpack-backup-pkg' ) }</li>
					<li>{ __( 'Global server infrastructure', 'jetpack-backup-pkg' ) }</li>
					<li>{ __( 'Best-in-class support', 'jetpack-backup-pkg' ) }</li>
				</ul>
			</Col>
			<Col lg={ 1 } md={ 1 } sm={ 0 } />
			<Col lg={ 5 } md={ 6 } sm={ 4 }>
				<PricingCard
					ctaText={ __( 'Get VaultPress Backup', 'jetpack-backup-pkg' ) }
					icon="data:image/svg+xml,%3Csvg width='32' height='32' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath fill-rule='evenodd' clip-rule='evenodd' d='m21.092 15.164.019-1.703v-.039c0-1.975-1.803-3.866-4.4-3.866-2.17 0-3.828 1.351-4.274 2.943l-.426 1.524-1.581-.065a2.92 2.92 0 0 0-.12-.002c-1.586 0-2.977 1.344-2.977 3.133 0 1.787 1.388 3.13 2.973 3.133H22.399c1.194 0 2.267-1.016 2.267-2.4 0-1.235-.865-2.19-1.897-2.368l-1.677-.29Zm-10.58-3.204a4.944 4.944 0 0 0-.201-.004c-2.75 0-4.978 2.298-4.978 5.133s2.229 5.133 4.978 5.133h12.088c2.357 0 4.267-1.97 4.267-4.4 0-2.18-1.538-3.99-3.556-4.339v-.06c0-3.24-2.865-5.867-6.4-5.867-2.983 0-5.49 1.871-6.199 4.404Z' fill='%23000'/%3E%3C/svg%3E"
					infoText={ priceAfter === price ? basicInfoText : introductoryInfoText }
					// eslint-disable-next-line react/jsx-no-bind
					onCtaClick={ sendToCart }
					priceAfter={ priceAfter }
					priceBefore={ price }
					currencyCode={ currencyCode }
					priceDetails={ priceDetails }
					title={ __( 'VaultPress Backup', 'jetpack-backup-pkg' ) }
				/>
			</Col>
		</Container>
	);
};

export default NoBackupCapabilities;
