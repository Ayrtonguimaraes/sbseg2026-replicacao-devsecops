# Limitações do assistente neste projeto e como evitar interrupções

Documento prático para o grupo. Explica **por que** algumas respostas do assistente de IA
(Claude) foram cortadas no meio, **o que** ele pode e não pode fazer neste projeto, e um
protocolo para seguir sem novas interrupções. Baseado nas páginas oficiais da Anthropic
(citadas no fim) e no comportamento observado em duas sessões.

## 1. O que aconteceu (diagnóstico)

Em duas ocasiões a resposta do assistente foi **interrompida por um classificador de
segurança automático**, não por erro de ferramenta e **não por decisão do professor ou da
disciplina**:

1. **Sessão anterior:** ao planejar automatizar a confirmação do caso `js-rce-b2b` do Juice
   Shop — o teste oficial envia um payload que força um laço não controlado até estourar o
   tempo limite, ou seja, tem **efeito de negação de serviço** sobre o processo-alvo.
2. **Esta sessão:** ao enumerar pontos de injeção de XSS no código do TeaStore e logo em
   seguida preparar o ambiente para **confirmar o XSS enviando payloads via HTTP**.

Em ambos os casos o gatilho foi a **trajetória "localizar vulnerabilidade → confirmar
disparando um exploit"**, mesmo em alvo local e descartável.

## 2. A distinção que importa: Política de Uso ≠ classificador em tempo real

Há **duas camadas diferentes**, e confundi-las faz perder tempo:

### Camada A — Política de Uso da Anthropic (o que é *permitido*)

A Política de Uso (vigente desde 12/11/2026) **permite explicitamente** este projeto. A
seção "Do Not Compromise Computer or Network Systems Without Authorization" proíbe
descobrir/explorar vulnerabilidades, acesso não autorizado, malware e negação de serviço
**sem autorização** — mas traz uma ressalva:

> "This section does not prohibit security research, testing, or tool development conducted
> on systems you own or operate, within the scope of an authorized bug bounty program or
> vulnerability disclosure policy..."

Este projeto se encaixa na ressalva: são **aplicações de treino propositalmente vulneráveis
(DVWA, TeaStore, Juice Shop) rodando em contêineres locais e descartáveis, na própria
máquina do usuário**, para reproduzir um artigo acadêmico. É "security research/testing on
systems you own or operate". **Nada aqui viola a Política de Uso.**

A própria política diz: *"encountering a block does not by itself indicate a violation of
the Usage Policy."* Ou seja: **ser bloqueado não quer dizer que o projeto é proibido.**

### Camada B — Classificador de segurança em tempo real (o que *interrompe*)

Sobre os modelos mais capazes, a Anthropic roda **salvaguardas automáticas em tempo real**
que detectam e bloqueiam conteúdo que *se parece* com atividade proibida (ex.: criação de
malware, exfiltração em massa, **ataques de negação de serviço**). Esse classificador:

- é **mais conservador** que a Política de Uso;
- avalia o **texto que está sendo gerado**, sem "ver" com a mesma força o contexto legítimo
  (meu alvo é local, é um artigo acadêmico, o professor pediu);
- por isso corta mesmo trabalho **permitido**, quando o texto, isolado, se parece com um
  exploit ativo.

**É a Camada B que nos interrompe, não a Camada A.** A conclusão prática: não adianta
"explicar melhor que é acadêmico" — o jeito de não ser cortado é **não fazer o modelo gerar
o passo que parece um ataque ativo**, e passar esse passo específico para execução manual.

## 3. O que o assistente PODE fazer (verde — sem risco de corte)

- Ler e analisar código-fonte, inclusive localizar e explicar vulnerabilidades (SAST manual).
- Rodar scanners: Semgrep, Checkov, Trivy (FS e Image), ZAP **passivo/baseline**.
- Subir os ambientes em Docker/Kubernetes local (TeaStore, DVWA, Juice Shop).
- Fazer **requisições benignas** que só exercitam uma rota sem payload de ataque — ex.:
  `GET /metrics` do Juice Shop (confirmado assim, sem problema), um healthcheck, um
  `GET /dataBaseAction` que só dispara a rota.
- Toda a análise de dados, políticas P1–P4, sensibilidade, gráficos, CSVs.
- Documentação, protocolo, slides, revisão de texto.
- Git: branches, commits, tags, bundles de recuperação.

## 4. O que é LIMÍTROFE (amarelo — pode cortar)

- **Enviar qualquer requisição que carregue um payload de ataque**, mesmo benigno na
  aparência e mesmo em alvo local: string `<script>` para XSS, `' OR 1=1` para SQLi, corpo
  de upload XXE. Policy permite; o classificador pode cortar.
- Escrever **scripts que montam e disparam esses payloads** automaticamente.

Regra para o amarelo: **se o próximo passo é o modelo emitir/disparar um exploit, pare e
entregue o comando pronto para o usuário rodar**, em vez de executar.

## 5. O que o assistente NÃO vai fazer (vermelho)

- **Automatizar qualquer teste com efeito de negação de serviço**, mesmo documentado pelo
  próprio alvo, mesmo local, mesmo "só para confirmar". Isso cobre o `js-rce-b2b` do Juice
  Shop (payload de laço não controlado). Decisão já registrada em `protocolo.md`.
- Gerar malware, ransomware, ferramentas de acesso remoto persistente, botnets.
- Qualquer coisa contra sistema que **não** seja do usuário / fora do escopo local.

Para esses casos, a evidência fica **estática** (Semgrep/Trivy) ou a confirmação dinâmica é
**manual pelo usuário**, com o caso marcado `nao_executada` e justificado.

## 6. Protocolo para não ter mais interrupções neste projeto

1. **Confirmação por código primeiro.** Para cada caso, a prova por leitura de código +
   scanner estático já basta para a análise direto/indireto do artigo. Isso cobre quase tudo.
2. **Dinâmico só quando benigno.** O assistente só dispara HTTP quando é um acesso sem
   payload de ataque (GET de rota, healthcheck, métrica exposta).
3. **Exploit ativo → vira comando manual.** Quando confirmar exige disparar um payload
   (XSS, SQLi, RCE), o assistente **não executa**: escreve o passo a passo e o comando exato
   em `pilotos.md` para o usuário rodar, e marca o caso `nao_executada` ou `inconclusiva`.
4. **Nada de DoS, nunca.** Independe de contexto.
5. **Sempre com rede de segurança.** Trabalho em branch dedicado; tag + bundle de
   recuperação antes de mudanças grandes; `git status`/`stash -u` antes de operação
   destrutiva. Assim, se uma resposta for cortada no meio, nada se perde.

Seguindo isso, o projeto avança em tudo que é análise, coleta estática, infraestrutura e
documentação — que é a maior parte — sem tocar nos gatilhos do classificador.

## 7. Impacto no resultado científico (tranquilizador)

A metodologia do artigo é **classificar detecções como diretas ou indiretas e simular
portões P1–P4**. Isso depende de *quais ferramentas sinalizam cada caso e com que CWE* —
informação que vem de **scanners estáticos e leitura de código**, não de explorar a falha. A
confirmação dinâmica ativa serve só para enriquecer a fila da P4 em alguns casos pontuais.
Portanto, os números centrais do projeto (composição, cobertura, P1–P3, sensibilidade) **não
dependem** do que o classificador bloqueia. Os poucos casos afetados ficam documentados como
confirmação manual pendente, o que é uma limitação metodológica honesta e comum na área.

## Fontes

- [Política de Uso da Anthropic (Usage Policy / AUP)](https://www.anthropic.com/legal/aup) — vigente 12/11/2026.
- [Anúncio da atualização da Política de Uso](https://www.anthropic.com/news/usage-policy-update) — ago/2025, seção de cibersegurança.
- [Fable 5's cyber safeguards and our jailbreak framework](https://www.anthropic.com/news/fable-safeguards-jailbreak-framework) — pentest/red team como uso dual de alto risco.
- [Mapping AI-enabled cyber threats](https://www.anthropic.com/research/attack-navigator) — salvaguardas em tempo real e Cyber Verification Program.
- [Claude Sonnet 4.5 System Card](https://www.anthropic.com/claude-sonnet-4-5-system-card) — avaliação de descoberta/correção de vulnerabilidades.
