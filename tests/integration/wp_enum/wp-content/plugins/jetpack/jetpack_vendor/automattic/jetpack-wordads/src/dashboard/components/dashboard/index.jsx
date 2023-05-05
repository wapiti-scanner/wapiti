import analytics from '@automattic/jetpack-analytics';
import restApi from '@automattic/jetpack-api';
import { Spinner, AdminSection, AdminPage, Container, Col } from '@automattic/jetpack-components';
import { useSelect, useDispatch, select as syncSelect } from '@wordpress/data';
import { __ } from '@wordpress/i18n';
import NoticesList from 'components/global-notices';
import ModuleControl from 'components/module-control';
import React, { Fragment, useMemo } from 'react';
import { STORE_ID } from 'store';

import 'scss/rna-styles.scss';
import './style.scss';

/**
 * WordAdsDashboard component definition.
 *
 * @returns {React.Component} Search dashboard component.
 */
export default function WordAdsDashboard() {
	useSelect( select => select( STORE_ID ).getWordAdsModuleStatus(), [] );

	const siteAdminUrl = useSelect( select => select( STORE_ID ).getSiteAdminUrl() );
	const aboutPageUrl = siteAdminUrl + 'admin.php?page=jetpack_about';

	const updateOptions = useDispatch( STORE_ID ).updateJetpackSettings;
	const isModuleEnabled = useSelect( select => select( STORE_ID ).isModuleEnabled() );
	const isSavingOptions = useSelect( select => select( STORE_ID ).isUpdatingJetpackSettings() );
	const isTogglingModule = useSelect( select => select( STORE_ID ).isTogglingModule() );

	const isLoading = useSelect(
		select =>
			select( STORE_ID ).isResolving( 'getWordAdsModuleStatus' ) ||
			! select( STORE_ID ).hasStartedResolution( 'getWordAdsModuleStatus' )
	);

	const handleLocalNoticeDismissClick = useDispatch( STORE_ID ).removeNotice;
	const notices = useSelect( select => select( STORE_ID ).getNotices(), [] );

	const initializeAnalytics = () => {
		const tracksUser = syncSelect( STORE_ID ).getWpcomUser();
		const blogId = syncSelect( STORE_ID ).getBlogId();

		if ( tracksUser ) {
			analytics.initialize( tracksUser.ID, tracksUser.login, {
				blog_id: blogId,
			} );
		}
	};

	useMemo( () => {
		const apiRootUrl = syncSelect( STORE_ID ).getAPIRootUrl();
		const apiNonce = syncSelect( STORE_ID ).getAPINonce();
		apiRootUrl && restApi.setApiRoot( apiRootUrl );
		apiNonce && restApi.setApiNonce( apiNonce );
		initializeAnalytics();
		analytics.tracks.recordEvent( 'jetpack_wordads_admin_page_view', {
			current_version: syncSelect( STORE_ID ).getVersion(),
		} );
	}, [] );

	return (
		<Fragment>
			{ isLoading && (
				<Spinner className="jp-wordads-dashboard-page-loading-spinner" color="#000" size={ 32 } />
			) }
			{ ! isLoading && (
				<AdminPage a8cLogoHref={ aboutPageUrl } moduleName={ __( 'WordAds', 'jetpack-wordads' ) }>
					<AdminSection>
						<Container horizontalSpacing={ 5 }>
							<Col sm={ 4 }>
								<ModuleControl
									updateOptions={ updateOptions }
									isModuleEnabled={ isModuleEnabled }
									isSavingOptions={ isSavingOptions }
									isTogglingModule={ isTogglingModule }
								/>
							</Col>
						</Container>
					</AdminSection>
				</AdminPage>
			) }
			<NoticesList
				notices={ notices }
				handleLocalNoticeDismissClick={ handleLocalNoticeDismissClick }
			/>
		</Fragment>
	);
}
