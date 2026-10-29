/* global eauthSpfApi */

const { __ } = wp.i18n;

jQuery(($) => {
	const checker = EmailAuthPlugin.instance.makeChecker(
		'spf',
		'SPF',
		() => `${eauthSpfApi.check}/${EmailAuthPlugin.instance.bounceDomain}`,
		() => {
			if (EmailAuthPlugin.instance.bounceDomain === null) {
				return {
					pass: null,
					reason: __('Unknown bounce address domain.', 'email-auth'),
				};
			}
		},
		(res) => {
			const out = [
				$('<h3>').text(__('SPF Check Result', 'email-auth')),
				$('<div>').append(
					__('Result code:', 'email-auth'),
					' ',
					$('<code>').text(res.code),
					' ',
					__('for server', 'email-auth'),
					' ',
					$('<code>').text(res.server_ip),
					' ',
					$('<button>')
						.attr('type', 'button')
						.text(__('Configure Server IP', 'email-auth'))
						.addClass('button-link')
						.on('click', () =>
							$('#eauth-spf-set-ip-dialog')[0].showModal()
						)
				),
				EmailAuthPlugin.createCommentList(
					res.code_reasons,
					__('Details', 'email-auth'),
					'h4'
				),
			];

			if (res.validity === false) {
				out.push(
					$('<h3>').text(__('Validity Check', 'email-auth')),
					$('<div>').append(
						`${EmailAuthPlugin.EMOJIS.error} ${__(
							'No syntactically valid record found.',
							'email-auth'
						)}`
					)
				);
			} else if (!res.validity.length) {
				out.push(
					$('<h3>').text(__('Validity Check', 'email-auth')),
					$('<div>').append(
						`${EmailAuthPlugin.EMOJIS.pass} ${__(
							'Current record is schematically valid.',
							'email-auth'
						)}`
					)
				);
			} else {
				out.push(
					EmailAuthPlugin.createCommentList(
						res.validity,
						__('Validity Check', 'email-auth')
					)
				);
			}

			if (res.rec_dns) {
				out.push(
					$('<h3>').text(__('Suggested DNS Record', 'email-auth'))
				);

				out.push(
					EmailAuthPlugin.createTxtRecord(
						EmailAuthPlugin.instance.bounceDomain,
						res.rec_dns
					),
					EmailAuthPlugin.createCommentList(
						res.rec_reasons,
						__('Reasons', 'email-auth'),
						'h4'
					)
				);
			}

			return out;
		},
		{
			get: () => EmailAuthPlugin.instance.bounceDomain,
			type: __('Bounce Address', 'email-auth'),
			link: '#bounce-address',
		},
		{
			get: () => EmailAuthPlugin.instance.bounceDomain,
		}
	);

	checker.boundCheck();
	EmailAuthPlugin.instance.addEventListener(
		'bouncedomainchange',
		checker.boundCheck
	);

	$('#eauth-spf-set-ip').on('click', async (e) => {
		e.preventDefault();

		const mode = $('[name="eauth_spf_server_ip"]:checked').val().trim();
		const custom = $('[name="eauth_spf_server_ip_custom"]').val().trim();

		const res = await EmailAuthPlugin.request(
			`${eauthSpfApi.setIp}`,
			'POST',
			{
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ mode, custom }),
			}
		);

		if (!res.ok) {
			return;
		}

		const json = await res.json();

		const escapedMode = CSS.escape(json.mode);
		$('[name="eauth_spf_server_ip"][value="' + escapedMode + '"]').prop(
			'checked',
			true
		);

		$('[name="eauth_spf_server_ip_custom"]').val(json.custom || '');

		$('#eauth-spf-set-ip-dialog')[0].close();
		checker.boundCheck();
	});

	$('#eauth-spf-set-ip-close').on('click', (e) => {
		e.preventDefault();
		$('#eauth-spf-set-ip-dialog')[0].close();
	});
});
