class EAUTHRadioDependentListener {
	name;
	callback;
	modes;
	removeListener;

	constructor(name, callback, modes) {
		this.name = name;
		this.callback = callback;
		this.modes = modes;

		this.radioChanged();
		jQuery(`[name="${this.name}"]`).on('change', () => this.radioChanged());
	}

	radioChanged() {
		this.removeListener?.();

		const mode = jQuery(`[name="${this.name}"]:checked`).val();
		const modeData = this.modes[mode];
		const target = modeData.target?.();
		const listener = () => this.callback(modeData.value(target));

		listener();

		if (!target) {
			return;
		}

		if (target instanceof jQuery) {
			target.on(modeData.event, listener);
			this.removeListener = () => target.off(modeData.event, listener);
			return;
		}

		target.addEventListener(modeData.event, listener);
		this.removeListener = () =>
			target.removeEventListener(modeData.event, listener);
	}
}

class EmailAuthPlugin extends EventTarget {
	static EMOJIS = {
		// Heading statuses
		pass: '✅',
		error: '❌',
		partial: '✅⚠️',
		unknown: '❔',
		// Only for individual items
		warning: '⚠️',
	};

	static #instance;

	static get instance() {
		if (!EmailAuthPlugin.#instance) {
			EmailAuthPlugin.#instance = new EmailAuthPlugin();
		}

		return EmailAuthPlugin.#instance;
	}

	static request(url, method, options = {}) {
		if (!options.headers) {
			options.headers = {};
		}

		options.method = options.method ?? method;
		options.headers['X-WP-Nonce'] = eauthCommonConfig.nonce;

		return fetch(url, options);
	}

	static getStatusDesc(pass) {
		if (pass === null || pass === undefined) {
			return 'unknown';
		}

		if (typeof pass === 'string') {
			return pass;
		}

		return pass ? 'pass' : 'error';
	}

	static createCommentList(comments, title, headingTag = 'h3') {
		if (!comments.length) {
			return;
		}

		return jQuery(`<${headingTag}>`)
			.text(title)
			.add(
				jQuery('<ul>').append(
					comments.map((comment) =>
						jQuery('<li>').html(
							comment.level
								? `${EmailAuthPlugin.EMOJIS[comment.level]} ${comment.desc}`
								: comment.desc
						)
					)
				)
			);
	}

	static createTxtRecord(host, record) {
		return jQuery('<div>')
			.addClass('eauth-dns-record')
			.append(
				jQuery('<dt>').append(
					'TXT record for ',
					jQuery('<code>').text(host)
				),
				jQuery('<dd>').text(record)
			);
	}

	static createCheckedDomain(domain, sourceLink, sourceName, fallbackDomain) {
		const el = jQuery('<div>');

		el.append(
			'Domain: ',
			jQuery('<span>').addClass('eauth-value').text(domain)
		);

		if (fallbackDomain) {
			el.append(
				' with fallback ',
				jQuery('<span>').addClass('eauth-value').text(fallbackDomain)
			);
		}

		el.append(
			' (from ',
			jQuery('<a>').attr('href', sourceLink).text(sourceName),
			')'
		);

		return el;
	}

	fromDomain;
	bounceDomain;
	fromAddress;

	#getFromAddressAndDomain() {
		const input = jQuery('[name="eauth_from_address"]');
		const address = input.val() || input.attr('placeholder');
		const parts = address.split('@');
		const domain = parts[1] ?? eauthCommonConfig.domain;

		this.fromDomain = domain;
		this.dispatchEvent(new CustomEvent('fromdomainchange'));

		this.fromAddress = `${parts[0]}@${domain}`;
		this.dispatchEvent(new CustomEvent('fromaddresschange'));
	}

	domReady() {
		this.#getFromAddressAndDomain();

		jQuery('[name="eauth_from_address"]').on('change', () =>
			this.#getFromAddressAndDomain()
		);

		new EAUTHRadioDependentListener(
			'eauth_bounce_address_mode',
			(val) => {
				this.bounceDomain = val;
				this.dispatchEvent(new CustomEvent('bouncedomainchange'));
			},
			{
				'': {
					value: () => null,
				},
				custom: {
					target: () => jQuery('[name="eauth_bounce_address"]'),
					event: 'change',
					value: (target) => {
						const parts = target.val().split('@');
						return parts[1] ?? eauthCommonConfig.domain;
					},
				},
				from: {
					target: () => this,
					event: 'fromdomainchange',
					value: (target) => target.fromDomain,
				},
			}
		);
	}

	setStatus(checkType, statusEl, headingEl, status, msg) {
		statusEl.text(msg);
		headingEl.attr('data-status', status);
		this.dispatchEvent(new CustomEvent(`${checkType}`));
	}

	makeChecker(
		headingId,
		checkType,
		getRequestUrl,
		preCheck,
		process,
		domain
	) {
		const heading = jQuery(`#${headingId}`);
		const status = heading.nextUntil('.eauth-status + *').last();
		const output = heading.nextUntil('.eauth-output + *').last();

		function addFootnote(text) {
			status.append('*');
			output.prepend(`* ${text}`);
		}

		return async () => {
			status.empty();
			output.empty();

			const preCheckRes = preCheck?.();

			if (preCheckRes) {
				const desc = EmailAuthPlugin.getStatusDesc(preCheckRes.pass);
				status.text(
					`${EmailAuthPlugin.EMOJIS[desc]} ${preCheckRes.reason}`
				);
				heading.attr('data-status', desc);
				return;
			}

			status.text(`Loading ${checkType} record...`);

			const raw = await EmailAuthPlugin.request(getRequestUrl());
			const res = await raw.json();
			const domainName = domain.get(res);

			if (!res.pass) {
				status.text(`${EmailAuthPlugin.EMOJIS.error} ${res.reason}`);
				heading.attr('data-status', 'error');
			} else if (
				domainName.alignment &&
				domainName.alignment !== this.fromDomain
			) {
				status
					.empty()
					.append(
						`${EmailAuthPlugin.EMOJIS.partial} `,
						jQuery('<a>')
							.attr('href', domain.link)
							.text(domain.type),
						domain.typeHasDomain ? '' : ' domain',
						' and ',
						jQuery('<a>')
							.attr('href', '#from-address')
							.text('From Address'),
						` domain do not match, so the from address domain cannot be verified through ${checkType}.`
					);
				heading.attr('data-status', 'partial');
			} else if (res.pass === 'partial') {
				status.text(
					`${EmailAuthPlugin.EMOJIS.partial} Configured with warnings.`
				);
				heading.attr('data-status', 'partial');
			} else {
				status.text(`${EmailAuthPlugin.EMOJIS.pass} Configured.`);
				heading.attr('data-status', 'pass');
			}

			output
				.empty()
				.append(
					EmailAuthPlugin.createCheckedDomain(
						domainName.record,
						domain.link,
						domain.type,
						domain.getFallback?.(res)
					)
				)
				.append(process(res, addFootnote));
		};
	}
}

jQuery(($) => {
	EmailAuthPlugin.instance.domReady();

	function setVariable(el, prefix, variable) {
		el.text(prefix).append(
			$('<span>')
				.addClass('value')
				.text(EmailAuthPlugin.instance[variable] ?? '?')
		);
	}

	$('.eauth-variable').each((_, domEl) => {
		const el = $(domEl);
		const prefix = el.data('prefix');
		const variable = el.data('variable');

		setVariable(el, prefix, variable);
		EmailAuthPlugin.instance.addEventListener(
			`${variable.toLowerCase()}change`,
			() => setVariable(el, prefix, variable)
		);
	});
});
