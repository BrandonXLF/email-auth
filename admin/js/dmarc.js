/* global eauthDmarcApi */

const { __, sprintf } = wp.i18n;

jQuery(($) => {
	const orgDomainCache = {};
	class OrgDomainError extends Error {}

	async function getOrgDomain(domain) {
		if (!orgDomainCache[domain]) {
			const response = await EmailAuthPlugin.request(
				`${eauthDmarcApi.org}/${domain}`
			);
			const data = await response.json();

			if (data.fail) {
				throw new OrgDomainError(data.fail);
			}

			orgDomainCache[domain] = data.org || domain;
		}

		return orgDomainCache[domain];
	}

	function makeStatusSetter(hasWarnings, setStatusInfo) {
		return (alignmentStatus, alignmentText, conjunction) => {
			conjunction =
				conjunction ??
				(hasWarnings
					? __('and', 'email-auth')
					: __('with', 'email-auth'));

			const statusCode =
				alignmentStatus === 'pass' && hasWarnings
					? 'partial'
					: alignmentStatus;

			const configuredPart = hasWarnings
				? __('Configured with warnings', 'email-auth')
				: __('Configured', 'email-auth');

			setStatusInfo(
				statusCode,
				`${configuredPart} ${conjunction} ${alignmentText}.`
			);
		};
	}

	// Note: Returned object's desc value is an HTML string.
	async function runAlignmentCheck(
		name,
		result,
		validateDomain,
		fromDomain,
		relaxed
	) {
		const escapedName = EmailAuthPlugin.escapeHtml(name);

		if (result === false) {
			return {
				level: 'error',
				desc: sprintf(
					/* translators: %s: alignment check name (DKIM or SPF) */
					__('%s check failed.', 'email-auth'),
					escapedName
				),
			};
		}

		if (validateDomain === null) {
			return {
				level: 'unknown',
				desc: sprintf(
					/* translators: %s: alignment check name (DKIM or SPF) */
					__('%s alignment unknown.', 'email-auth'),
					escapedName
				),
			};
		}

		try {
			if (relaxed && validateDomain !== fromDomain) {
				validateDomain = await getOrgDomain(validateDomain);
				fromDomain = await getOrgDomain(fromDomain);
			}
		} catch (error) {
			if (error instanceof OrgDomainError) {
				return { level: 'unknown', desc: error.message };
			}

			throw error;
		}

		if (validateDomain !== fromDomain) {
			return {
				level: 'error',
				desc: sprintf(
					/* translators: 1: validated domain, 2: from domain */
					__(
						'%1$s alignment failed: %2$s does not match from domain %3$s.',
						'email-auth'
					),
					escapedName,
					EmailAuthPlugin.escapeHtml(validateDomain),
					EmailAuthPlugin.escapeHtml(fromDomain)
				),
			};
		}

		if (result === null) {
			return {
				level: 'unknown',
				desc: sprintf(
					/* translators: %s: alignment check name (DKIM or SPF) */
					__('%s result unknown.', 'email-auth'),
					escapedName
				),
			};
		}

		return {
			level: 'pass',
			desc: sprintf(
				/* translators: %s: alignment check name (DKIM or SPF) */
				__('%s alignment passed.', 'email-auth'),
				escapedName
			),
		};
	}

	function addAlignmentCheck(
		onRun,
		checkId,
		name,
		getDomain,
		domainEvent,
		relaxed
	) {
		const resultEvent = `${checkId}resultchange`;
		const plugin = EmailAuthPlugin.instance;

		const runCheck = async () =>
			onRun(
				await runAlignmentCheck(
					name,
					plugin.results[checkId],
					getDomain(),
					plugin.fromDomain,
					relaxed
				)
			);

		runCheck();
		plugin.addEventListener(resultEvent, runCheck);
		plugin.addEventListener(domainEvent, runCheck);
		plugin.addEventListener('fromdomainchange', runCheck);

		return () => {
			plugin.removeEventListener(resultEvent, runCheck);
			plugin.removeEventListener(domainEvent, runCheck);
			plugin.removeEventListener('fromdomainchange', runCheck);
		};
	}

	function addAlignmentChecks(relaxed, setAlignmentStatus) {
		const results = {
			dkim: {
				level: 'unknown',
				desc: __('Check in progress…', 'email-auth'),
			},
			spf: {
				level: 'unknown',
				desc: __('Check in progress…', 'email-auth'),
			},
		};

		const onRun = (checkId, result) => {
			results[checkId] = result;

			$('.eauth-dmarc-alignment-check-component')
				.first()
				.replaceWith(
					EmailAuthPlugin.createCommentList(
						Object.values(results),
						__('Alignment Checks', 'email-auth')
					).addClass('eauth-dmarc-alignment-check-component')
				)
				.end()
				.remove();

			const pass = Object.values(results).some(
				({ level }) => level === 'pass'
			);
			if (pass) {
				setAlignmentStatus('pass', __('alignment', 'email-auth'));
				return;
			}

			const unknown = Object.values(results).some(
				({ level }) => level === 'unknown'
			);
			if (unknown) {
				setAlignmentStatus(
					'incomplete',
					__('unknown alignment', 'email-auth')
				);
				return;
			}

			setAlignmentStatus(
				'error',
				__('alignment checks failed', 'email-auth'),
				__('but', 'email-auth')
			);
		};

		const disposeDKIMCheck = addAlignmentCheck(
			onRun.bind(null, 'dkim'),
			'dkim',
			'DKIM',
			() => EmailAuthPlugin.instance.extra.dkimDomain,
			'dkimdomainchange',
			relaxed.dkim
		);

		const disposeSPFCheck = addAlignmentCheck(
			onRun.bind(null, 'spf'),
			'spf',
			'SPF',
			() => EmailAuthPlugin.instance.bounceDomain,
			'bouncedomainchange',
			relaxed.spf
		);

		return () => {
			disposeDKIMCheck();
			disposeSPFCheck();
		};
	}

	const checker = EmailAuthPlugin.instance.makeChecker(
		'dmarc',
		'DMARC',
		() => `${eauthDmarcApi.check}/${EmailAuthPlugin.instance.fromDomain}`,
		null,
		(res) => {
			return [
				res.orgFail &&
					$('<div>')
						.addClass('notice inline multiline')
						.text(res.orgFail),
				$('<div>').attr(
					'class',
					'eauth-dmarc-alignment-check-component'
				),
				EmailAuthPlugin.createCommentList(
					res.warnings.map((desc) => ({
						level: 'warning',
						desc,
					})),
					__('Warnings', 'email-auth')
				),
				EmailAuthPlugin.createCommentList(
					res.infos.map((desc) => ({ desc })),
					__('Comments', 'email-auth')
				),
			];
		},
		{
			get: () => `_dmarc.${EmailAuthPlugin.instance.fromDomain}`,
			getFallback: (res) => res.org && `_dmarc.${res.org}`,
			type: __('From Address', 'email-auth'),
			link: '#from-address',
		},
		(res, setStatusInfo) => {
			if (!res.pass) {
				setStatusInfo('error', res.reason);
				return;
			}

			const setAlignmentStatus = makeStatusSetter(
				res.pass === 'partial',
				setStatusInfo
			);
			setAlignmentStatus(
				'incomplete',
				__('unknown alignments', 'email-auth')
			);

			return addAlignmentChecks(res.relaxed, setAlignmentStatus);
		}
	);

	checker.boundCheck();
	EmailAuthPlugin.instance.addEventListener(
		'fromdomainchange',
		checker.boundCheck
	);
});
