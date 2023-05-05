import apiFetch from '@wordpress/api-fetch';
import actions from '../index';
import {
	SITE_BACKUP_POLICIES_GET,
	SITE_BACKUP_POLICIES_GET_FAILED,
	SITE_BACKUP_POLICIES_GET_SUCCESS,
} from '../types';

const anyFunction = () => {};
jest.mock( '@wordpress/api-fetch' );

const apiFixtures = {
	requestOptions: {
		path: '/jetpack/v4/site/backup/policies',
	},
	successWithPoliciesResponse: {
		policies: {
			activity_log_limit_days: 30,
			storage_limit_bytes: 7516192768,
		},
	},
	successWithNoPoliciesResponse: {
		policies: null,
	},
	failureResponse: '',
};

const successWithPoliciesPayload = {
	activityLogLimitDays: 30,
	storageLimitBytes: 7516192768,
};

const successWithNoPoliciesPayload = {
	activityLogLimitDays: null,
	storageLimitBytes: null,
};

describe( 'getSiteSize', () => {
	beforeEach( () => jest.clearAllMocks() );

	it( 'dispatches SITE_BACKUP_SIZE_GET and SITE_BACKUP_POLICIES_GET_SUCCESS with policy when fetches site with policies', async () => {
		const dispatch = jest.fn( anyFunction );
		apiFetch.mockReturnValue( Promise.resolve( apiFixtures.successWithPoliciesResponse ) );

		await actions.getSitePolicies()( { dispatch } );
		expect( apiFetch ).toHaveBeenCalledWith( apiFixtures.requestOptions );

		expect( dispatch ).toHaveBeenCalledTimes( 2 );
		expect( dispatch ).toHaveBeenCalledWith( {
			type: SITE_BACKUP_POLICIES_GET,
		} );
		expect( dispatch ).toHaveBeenCalledWith( {
			type: SITE_BACKUP_POLICIES_GET_SUCCESS,
			payload: successWithPoliciesPayload,
		} );
	} );

	it.each( [
		{
			apiMockResponse: apiFixtures.successWithNoPoliciesResponse,
		},
		{
			apiMockResponse: apiFixtures.failureResponse,
		},
		{
			apiMockResponse: '',
		},
	] )(
		'dispatches SITE_BACKUP_SIZE_GET and SITE_BACKUP_POLICIES_GET_SUCCESS with no policy when fetches site without policies',
		async ( { apiMockResponse } ) => {
			const dispatch = jest.fn( anyFunction );

			apiFetch.mockReturnValue( Promise.resolve( apiMockResponse ) );
			await actions.getSitePolicies()( { dispatch } );

			expect( apiFetch ).toHaveBeenCalledWith( apiFixtures.requestOptions );

			expect( dispatch ).toHaveBeenCalledTimes( 2 );
			expect( dispatch ).toHaveBeenCalledWith( {
				type: SITE_BACKUP_POLICIES_GET,
			} );
			expect( dispatch ).toHaveBeenCalledWith( {
				type: SITE_BACKUP_POLICIES_GET_SUCCESS,
				payload: successWithNoPoliciesPayload,
			} );
		}
	);

	it( 'dispatches SITE_BACKUP_SIZE_GET and SITE_BACKUP_POLICIES_GET_FAILED when API call fails', async () => {
		const dispatch = jest.fn( anyFunction );
		apiFetch.mockReturnValue( Promise.reject( 'Timeout error' ) );

		await actions.getSitePolicies()( { dispatch } );
		expect( apiFetch ).toHaveBeenCalledWith( apiFixtures.requestOptions );

		expect( dispatch ).toHaveBeenCalledTimes( 2 );
		expect( dispatch ).toHaveBeenCalledWith( {
			type: SITE_BACKUP_POLICIES_GET,
		} );
		expect( dispatch ).toHaveBeenCalledWith( {
			type: SITE_BACKUP_POLICIES_GET_FAILED,
		} );
	} );
} );
