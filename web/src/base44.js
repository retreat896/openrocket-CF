// Cloudflare local adapter. This keeps the original OpenRocket browser pages and room protocol
// unchanged while replacing Base44 with the Rust Worker, D1 and Durable Objects.

async function request(path, { method = 'GET', body, headers = {} } = {}) {
  const options = { method, headers: { 'X-ORC-Client': '1', ...headers }, credentials: 'same-origin' };
  if (body !== undefined) {
    if (body instanceof Uint8Array) {
      options.body = body;
    } else if (body instanceof Blob) {
      options.body = body;
    } else if (typeof body === 'string') {
      options.body = body;
    } else {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
  }
  const response = await fetch(path, options);
  const text = await response.text();
  let value = null;
  try {
    value = text ? JSON.parse(text) : null;
  } catch {
    value = text;
  }
  if (!response.ok) {
    const error = new Error(value?.error || value || `Request failed (${response.status})`);
    error.code = value?.code ?? null;
    throw error;
  }
  return value;
}

export async function api(name, body) {
  try {
    if (name === 'designs') {
      const action = body?.action;
      if (action === 'list') return request('/api/projects').then((projects) => projects.map((project) => ({
        id: project.id,
        name: project.name,
        role: project.role,
        owner_id: project.owner?.id,
        owner_email: project.owner?.email,
        owner_name: project.owner?.name,
        members: project.members ?? [],
        preview: project.preview ?? null,
        updated_date: project.updatedAt ? new Date(project.updatedAt).toISOString() : null,
        edited_at: project.updatedAt ? new Date(project.updatedAt).toISOString() : null,
      })));
      if (action === 'get') return request(`/api/projects/${encodeURIComponent(body.id)}`).then((project) => ({
        id: project.id,
        name: project.name,
        role: project.role,
        owner_id: project.owner?.id,
        owner_email: project.owner?.email,
        owner_name: project.owner?.name,
        members: project.members ?? [],
        preview: project.preview ?? null,
        updated_date: project.updatedAt ? new Date(project.updatedAt).toISOString() : null,
      }));
      if (action === 'create') return request('/api/projects', { method: 'POST', body: { name: body.name } });
      if (action === 'rename') return request(`/api/projects/${encodeURIComponent(body.id)}`, { method: 'PATCH', body: { name: body.name } });
      if (action === 'delete') return request(`/api/projects/${encodeURIComponent(body.id)}`, { method: 'DELETE' });
      if (action === 'leave') return currentUser().then((me) => request(`/api/projects/${encodeURIComponent(body.id)}/members/${encodeURIComponent(me.email)}`, { method: 'DELETE' }));
      if (action === 'members') return request(`/api/projects/${encodeURIComponent(body.id)}/members`, {
        method: 'POST',
        body: { email: body.email, role: body.role },
      });
      if (action === 'preview') return request(`/api/projects/${encodeURIComponent(body.id)}/preview`, { method: 'POST', body: { preview: body.preview } });
      throw new Error(`Unsupported designs action: ${action}`);
    }

    if (name === 'motors') {
      const action = body?.action;
      if (action === 'list') return request('/api/motors');
      if (action === 'add') return request('/api/motors', {
        method: 'POST',
        body: body.content,
        headers: { 'X-Filename': encodeURIComponent(body.filename ?? 'motor.eng'), 'Content-Type': 'text/plain' },
      });
      if (action === 'delete') return request(`/api/motors/${encodeURIComponent(body.id)}`, { method: 'DELETE' });
      if (action === 'motors') return request(`/api/projects/${encodeURIComponent(body.id)}/motors`);
      throw new Error(`Unsupported motors action: ${action}`);
    }

    if (name === 'gfsWinds') {
      const lat = Number(body?.lat);
      const lon = Number(body?.lon);
      const time = new Date(String(body?.time ?? ''));
      if (!Number.isFinite(lat) || !Number.isFinite(lon) || Number.isNaN(time.getTime())) {
        throw new Error('Give a launch site (lat, lon) and time.');
      }
      const start = time.toISOString().slice(0, 10);
      const endDate = new Date(time);
      endDate.setUTCDate(endDate.getUTCDate() + 1);
      const end = endDate.toISOString().slice(0, 10);
      const fields = [
        'temperature_2m',
        'surface_pressure',
        'pressure_msl',
        'wind_speed_10m',
        'wind_direction_10m',
        'wind_speed_80m',
        'wind_direction_80m',
        'wind_speed_120m',
        'wind_direction_120m',
        'wind_speed_180m',
        'wind_direction_180m',
      ].join(',');
      const url = new URL('https://api.open-meteo.com/v1/forecast');
      url.searchParams.set('latitude', String(lat));
      url.searchParams.set('longitude', String(lon));
      url.searchParams.set('hourly', fields);
      url.searchParams.set('wind_speed_unit', 'ms');
      url.searchParams.set('temperature_unit', 'celsius');
      url.searchParams.set('timezone', 'UTC');
      url.searchParams.set('start_date', start);
      url.searchParams.set('end_date', end);
      url.searchParams.set('models', 'gfs_seamless');

      let response;
      try {
        response = await fetch(url, { headers: { Accept: 'application/json' } });
      } catch {
        throw new Error('Could not get the forecast. Try again in a moment.');
      }
      if (!response.ok) {
        throw new Error(response.status === 429
          ? 'The forecast service is busy. Try again in a few minutes.'
          : 'Could not get the forecast. Try again in a moment.');
      }
      const data = await response.json();
      const hourly = data.hourly;
      if (!hourly?.time?.length) {
        throw new Error('The forecast service did not return winds. Try again in a moment.');
      }

      const target = time.getTime();
      let index = 0;
      for (let i = 0; i < hourly.time.length; i++) {
        if (new Date(`${hourly.time[i]}Z`).getTime() <= target) index = i;
        else break;
      }
      const i0 = index;
      const i1 = Math.min(hourly.time.length - 1, i0 + 1);
      const t0 = new Date(`${hourly.time[i0]}Z`).getTime();
      const t1 = new Date(`${hourly.time[i1]}Z`).getTime();
      const fraction = t1 > t0 ? Math.max(0, Math.min(1, (target - t0) / (t1 - t0))) : 0;
      const mix = (a, b) => (a == null ? b : b == null ? a : a + (b - a) * fraction);
      const profileAt = (height) => {
        const samples = [
          [10, '10m'],
          [80, '80m'],
          [120, '120m'],
          [180, '180m'],
        ].map(([agl, suffix]) => {
          const speed0 = Number(hourly[`wind_speed_${suffix}`]?.[i0]);
          const speed1 = Number(hourly[`wind_speed_${suffix}`]?.[i1]);
          const dir0 = Number(hourly[`wind_direction_${suffix}`]?.[i0]);
          const dir1 = Number(hourly[`wind_direction_${suffix}`]?.[i1]);
          const speed = mix(Number.isFinite(speed0) ? speed0 : null, Number.isFinite(speed1) ? speed1 : null);
          const dir = mix(Number.isFinite(dir0) ? dir0 : null, Number.isFinite(dir1) ? dir1 : null);
          if (speed == null || dir == null) return [agl, null, null];
          const radians = dir * Math.PI / 180;
          return [agl, -speed * Math.sin(radians), -speed * Math.cos(radians)];
        }).filter(([, u, v]) => u != null && v != null);

        if (!samples.length) return [height, null, null];
        if (height <= samples[0][0]) return [height, samples[0][1], samples[0][2]];
        if (height >= samples[samples.length - 1][0]) return [height, samples[samples.length - 1][1], samples[samples.length - 1][2]];
        for (let i = 0; i < samples.length - 1; i++) {
          const [h0, u0, v0] = samples[i];
          const [h1, u1, v1] = samples[i + 1];
          if (height <= h1) {
            const f = (height - h0) / (h1 - h0);
            return [height, u0 + (u1 - u0) * f, v0 + (v1 - v0) * f];
          }
        }
        return [height, null, null];
      };

      const aglLevels = [10, 20, 30, 40, 50, 80, 100, 120, 180];
      const temp0 = Number(hourly.temperature_2m?.[i0]);
      const temp1 = Number(hourly.temperature_2m?.[i1]);
      const temperature = mix(Number.isFinite(temp0) ? temp0 : null, Number.isFinite(temp1) ? temp1 : null);
      const pressure0 = Number(hourly.surface_pressure?.[i0]);
      const pressure1 = Number(hourly.surface_pressure?.[i1]);
      const pressureAt0 = Number.isFinite(pressure0)
        ? pressure0
        : (Number.isFinite(Number(hourly.pressure_msl?.[i0])) ? Number(hourly.pressure_msl?.[i0]) : null);
      const pressureAt1 = Number.isFinite(pressure1)
        ? pressure1
        : (Number.isFinite(Number(hourly.pressure_msl?.[i1])) ? Number(hourly.pressure_msl?.[i1]) : null);
      const surfacePressure = mix(pressureAt0, pressureAt1);

      const levels = aglLevels.map((agl) => {
        const [, u, v] = profileAt(agl);
        const temp = temperature == null ? null : temperature - 0.0065 * agl;
        const pressure = surfacePressure == null ? null : surfacePressure * Math.exp(-agl / 8434);
        return { agl, u: u ?? 0, v: v ?? 0, t: temp == null ? null : temp + 273.15, p: pressure == null ? null : pressure };
      });

      const firstTime = hourly.time[0];
      const run = new Date(`${firstTime}Z`);
      return {
        model: 'NOAA GFS via Open-Meteo',
        run: Number.isNaN(run.getTime()) ? time.toISOString() : run.toISOString(),
        valid: time.toISOString(),
        lat,
        lon,
        ground: data.elevation ?? 0,
        levels,
        ensemble: { error: 'Ensemble forecast is not available; the planner is using GFS winds with its normal spread.' },
      };
    }

    if (name === 'flights' || name === 'logbooks') return [];
    throw new Error(`Unsupported API: ${name}`);
  } catch (error) {
    if (error.code === 'plan_required' || error.code === 'plan_upgrade') {
      window.dispatchEvent(new CustomEvent('plan-required', { detail: { message: error.message, code: error.code } }));
    }
    throw error;
  }
}

export async function currentUser() {
  try {
    const user = await request('/api/me');
    return user ? {
      id: user.id,
      email: user.email,
      name: user.name,
      full_name: user.name,
      picture: user.picture,
    } : null;
  } catch (error) {
    if (error.message === 'Please sign in.') return null;
    throw error;
  }
}

export function signIn(to = location.href) {
  const target = new URL(to, location.href);
  location.href = `/auth.html?next=${encodeURIComponent(target.pathname + target.search + target.hash)}`;
}

export async function signOut() {
  await request('/auth/logout', { method: 'POST' });
  location.href = '/';
}

export const base44 = {
  functions: {
    invoke: async (name, body) => ({ data: await api(name, body) }),
  },
  auth: {
    me: currentUser,
    logout: signOut,
  },
  actors: {
    DesignRoom: () => {
      throw new Error('The design room uses native WebSockets through room-client.js.');
    },
  },
  integrations: {
    Core: {
      UploadPrivateFile: async () => ({ file_uri: '' }),
    },
  },
};
