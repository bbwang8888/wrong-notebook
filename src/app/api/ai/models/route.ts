import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { unauthorized } from '@/lib/api-errors';
import { createLogger } from '@/lib/logger';
import { checkOutboundUrl } from '@/lib/ssrf-guard';

const logger = createLogger('api:ai:models');

interface ModelInfo {
    id: string;
    name: string;
    owned_by?: string;
}

// 从模型 ID 中提取短名称
function extractModelName(modelId: string): string {
    // models/gemini-2.0-flash -> gemini-2.0-flash
    return modelId.replace(/^models\//, '');
}

async function fetchGeminiModels(apiKey: string, baseUrl: string): Promise<ModelInfo[]> {
    const url = `${baseUrl}/v1beta/models?key=${apiKey}`;

    const response = await fetch(url, {
        headers: { 'Content-Type': 'application/json' },
    });

    if (!response.ok) {
        const errorText = await response.text();
        logger.error({ status: response.status, errorText }, 'Gemini models API error');
        throw new Error(`Gemini API error: ${response.status}`);
    }

    const data = await response.json();
    return (data.models || [])
        .map((m: any) => {
            const id = extractModelName(m.name);
            return {
                id,
                name: id,
                owned_by: 'Google',
            };
        });
}

async function fetchOpenAIModels(apiKey: string, baseUrl: string): Promise<ModelInfo[]> {
    const url = `${baseUrl}/models`;

    const response = await fetch(url, {
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
        },
    });

    if (!response.ok) {
        logger.error({ statusText: response.statusText }, 'OpenAI models API error');
        throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();

    return (data.data || [])
        .map((model: any) => ({
            id: model.id,
            name: model.id,
            owned_by: model.owned_by,
        }));
}

export async function GET(req: NextRequest) {
    // 该接口会用服务端身份去请求调用方指定的 baseUrl，
    // 未鉴权时可被用作 SSRF 跳板探测内网，故要求登录。
    const session = await getServerSession(authOptions);
    if (!session?.user) {
        return unauthorized("Authentication required");
    }

    // 自定义 baseUrl 等同于让服务器去任意地址发起请求，必须限制为管理员，
    // 并额外做一次内网地址过滤（见 src/lib/ssrf-guard.ts）。
    const isAdmin = (session.user as { role?: string }).role === 'admin';

    try {
        const { searchParams } = new URL(req.url);
        const provider = searchParams.get('provider');
        const apiKey = searchParams.get('apiKey');
        const baseUrl = searchParams.get('baseUrl');

        if (!apiKey) {
            return NextResponse.json(
                { error: 'API key is required' },
                { status: 400 }
            );
        }

        if (baseUrl) {
            if (!isAdmin) {
                return NextResponse.json(
                    { error: '仅管理员可指定自定义接口地址', models: [] },
                    { status: 403 }
                );
            }
            const check = checkOutboundUrl(baseUrl);
            if (!check.ok) {
                logger.warn({ baseUrl, reason: check.reason }, 'Blocked outbound URL');
                return NextResponse.json(
                    { error: `接口地址不被允许：${check.reason}`, models: [] },
                    { status: 400 }
                );
            }
        }

        let models: ModelInfo[] = [];

        if (provider === 'gemini') {
            const effectiveBaseUrl = baseUrl || 'https://generativelanguage.googleapis.com';
            models = await fetchGeminiModels(apiKey, effectiveBaseUrl);
        } else {
            // OpenAI-compatible
            const effectiveBaseUrl = baseUrl || 'https://api.openai.com/v1';
            models = await fetchOpenAIModels(apiKey, effectiveBaseUrl);
        }

        return NextResponse.json({ models });

    } catch (error: any) {
        logger.error({ error }, 'Error fetching models');
        // 不回传原始 error.message，避免泄露内部实现细节
        return NextResponse.json(
            { error: 'Failed to fetch models', models: [] },
            { status: 200 } // Return 200 with empty models to allow manual input
        );
    }
}
