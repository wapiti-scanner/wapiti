import analytics from '@automattic/jetpack-analytics';
import { __ } from '@wordpress/i18n';
import classNames from 'classnames';
import Card from 'components/card';
import CompactFormToggle from 'components/form-toggle/compact';
import React, { useCallback } from 'react';

import 'scss/rna-styles.scss';
import './style.scss';

const SEARCH_DESCRIPTION = __(
	'Earn income by allowing Jetpack to display high quality ads.',
	'jetpack-wordads'
);

/**
 * Search settings component to be used within the Performance section.
 *
 * @param {object} props - Component properties.
 * @param {Function} props.updateOptions - function to update settings.
 * @param {boolean} props.isSavingOptions - true if Saving options.
 * @param {boolean} props.isModuleEnabled - true if WordAds module is enabled.
 * @param {boolean} props.isTogglingModule - true if toggling WordAds module.
 * @returns {React.Component}	Search settings component.
 */
export default function WordAdsModuleControl( {
	updateOptions,
	isSavingOptions,
	isModuleEnabled,
	isTogglingModule,
} ) {
	const toggleSearchModule = useCallback( () => {
		const newOption = {
			module_active: ! isModuleEnabled,
		};
		updateOptions( newOption );
		analytics.tracks.recordEvent( 'jetpack_wordads_module_toggle', newOption );
	}, [ isModuleEnabled, updateOptions ] );

	const renderSearchToggle = () => {
		return (
			<div className="jp-form-wordads-settings-group__toggle is-search jp-wordads-dashboard-wrap">
				<div className="jp-wordads-dashboard-row">
					<div className="lg-col-span-2 md-col-span-1 sm-col-span-0"></div>
					<CompactFormToggle
						checked={ isModuleEnabled }
						disabled={ isSavingOptions }
						onChange={ toggleSearchModule }
						toggling={ isTogglingModule }
						className="is-wordads-admin"
						switchClassNames="lg-col-span-1 md-col-span-1 sm-col-span-1"
						labelClassNames=" lg-col-span-7 md-col-span-5 sm-col-span-3"
						aria-label={ __( 'Enable WordAds', 'jetpack-wordads' ) }
					>
						{ __( 'Enable WordAds', 'jetpack-wordads' ) }
					</CompactFormToggle>
					<div className="lg-col-span-2 md-col-span-1 sm-col-span-0"></div>
				</div>
				<div className="jp-wordads-dashboard-row">
					<div className="lg-col-span-3 md-col-span-2 sm-col-span-1"></div>
					<div className="jp-form-wordads-settings-group__toggle-description lg-col-span-7 md-col-span-5 sm-col-span-3">
						<p className="jp-form-wordads-settings-group__toggle-explanation">
							{ SEARCH_DESCRIPTION }
						</p>
					</div>
					<div className="lg-col-span-2 md-col-span-1 sm-col-span-0"></div>
				</div>
			</div>
		);
	};

	return (
		<div className="jp-form-settings-group jp-form-wordads-settings-group">
			<Card
				className={ classNames( {
					'jp-form-has-child': true,
					'jp-form-settings-disable': false,
				} ) }
			>
				<div className="jp-form-wordads-settings-group-inside">{ renderSearchToggle() }</div>
			</Card>
		</div>
	);
}
