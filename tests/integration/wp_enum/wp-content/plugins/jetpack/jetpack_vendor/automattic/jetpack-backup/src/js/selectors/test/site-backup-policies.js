import { expect } from '@jest/globals';
import selectors from '../site-backup';

describe( 'siteBackupPoliciesSelectors', () => {
	const fixtures = {
		emptyObject: {
			siteBackupPolicies: {},
		},
		initialState: {
			siteBackupPolicies: {
				isFetching: false,
				loaded: false,
				activityLogLimitDays: null,
				storageLimitBytes: null,
			},
		},
		fetchingState: {
			siteBackupPolicies: {
				isFetching: true,
				loaded: false,
				activityLogLimitDays: null,
				storageLimitBytes: null,
			},
		},
		failedState: {
			siteBackupPolicies: {
				isFetching: false,
				loaded: false,
				activityLogLimitDays: null,
				storageLimitBytes: null,
			},
		},
		successState: {
			siteBackupPolicies: {
				isFetching: false,
				loaded: true,
				activityLogLimitDays: 30,
				storageLimitBytes: 10737418240,
			},
		},
	};

	describe( 'isFetchingBackupPolicies()', () => {
		it.each( [
			{
				state: fixtures.emptyObject,
				expected: null,
			},
			{
				state: fixtures.initialState,
				expected: false,
			},
			{
				state: fixtures.fetchingState,
				expected: true,
			},
			{
				state: fixtures.failedState,
				expected: false,
			},
			{
				state: fixtures.successState,
				expected: false,
			},
		] )(
			'should return isFetching bool value if passed, false otherwise',
			( { state, expected } ) => {
				const output = selectors.isFetchingBackupPolicies( state );
				expect( output ).toBe( expected );
			}
		);
	} );

	describe( 'getBackupStorageLimit()', () => {
		it.each( [
			{
				state: fixtures.emptyObject,
				expected: null,
			},
			{
				state: fixtures.initialState,
				expected: null,
			},
			{
				state: fixtures.fetchingState,
				expected: null,
			},
			{
				state: fixtures.failedState,
				expected: null,
			},
			{
				state: fixtures.successState,
				expected: 10737418240,
			},
		] )(
			'should return storageLimitBytes value if passed, null otherwise',
			( { state, expected } ) => {
				const output = selectors.getBackupStorageLimit( state );
				expect( output ).toBe( expected );
			}
		);
	} );

	describe( 'getActivityLogLimitDays()', () => {
		it.each( [
			{
				state: fixtures.emptyObject,
				expected: null,
			},
			{
				state: fixtures.initialState,
				expected: null,
			},
			{
				state: fixtures.fetchingState,
				expected: null,
			},
			{
				state: fixtures.failedState,
				expected: null,
			},
			{
				state: fixtures.successState,
				expected: 30,
			},
		] )(
			'should return activityLogLimitDays value if passed, null otherwise',
			( { state, expected } ) => {
				const output = selectors.getActivityLogLimitDays( state );
				expect( output ).toBe( expected );
			}
		);
	} );
} );
