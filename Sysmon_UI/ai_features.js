// AI Features JavaScript Module
class AISecurityAssistant {
    constructor() {
        this.analysisData = null;
        this.chatHistory = [];
    }

    async runAIAnalysis() {
        try {
            // Simulate AI analysis (in real implementation, this would call backend)
            console.log('🤖 Starting AI analysis...');
            
            // Show loading state
            this.updateAIInsights({
                totalEvents: '...',
                anomaliesDetected: '...',
                highRiskEvents: '...',
                aiConfidence: '...'
            });

            // Simulate processing time
            await new Promise(resolve => setTimeout(resolve, 2000));

            // Mock AI analysis results
            const mockResults = {
                totalEvents: 279,
                anomaliesDetected: 12,
                highRiskEvents: 5,
                mediumRiskEvents: 4,
                lowRiskEvents: 3,
                aiConfidence: 87,
                threatPatterns: [
                    'Suspicious PowerShell activity',
                    'Unusual network connections',
                    'Temp folder execution'
                ],
                explanations: [
                    {
                        time: '22:30',
                        process: 'svchost.exe',
                        risk: 92,
                        explanation: '🚨 **CRITICAL THREAT DETECTED**: svchost.exe is exhibiting highly suspicious behavior. The activity involves Suspicious process pattern: svchost.exe, Suspicious path pattern: \\AppData\\Local\\Temp\\ which are commonly associated with malware campaigns. Immediate investigation recommended. This pattern matches known attack techniques: T1083 - File and Directory Discovery.',
                        threats: ['critical', 'malware', 'network']
                    },
                    {
                        time: '23:10',
                        process: 'cmd.exe',
                        risk: 84,
                        explanation: '⚠️ **SUSPICIOUS ACTIVITY**: cmd.exe behavior requires attention. Detected Suspicious process pattern: cmd.exe.*\/c, Process reputation: medium_risk that could indicate potential security concerns. Monitor this activity closely. Related MITRE techniques: T1059.003 - Command Shell.',
                        threats: ['suspicious', 'command']
                    },
                    {
                        time: '00:55',
                        process: 'temp.exe',
                        risk: 88,
                        explanation: '🚨 **CRITICAL THREAT DETECTED**: temp.exe is exhibiting highly suspicious behavior. The activity involves Suspicious file type: \.exe$, Suspicious path pattern: \\AppData\\Local\\Temp\\ which are commonly associated with malware campaigns. Immediate investigation recommended.',
                        threats: ['critical', 'file', 'malware']
                    }
                ]
            };

            this.analysisData = mockResults;
            this.updateAIInsights(mockResults);
            this.displayAIExplanations(mockResults.explanations);
            this.updateThreatsTable(mockResults.explanations);

            // Show AI sections
            document.getElementById('aiInsights').classList.remove('hidden');
            document.getElementById('aiChat').classList.remove('hidden');
            document.getElementById('aiExplanationBtn').style.display = 'block';

            return mockResults;
        } catch (error) {
            console.error('AI Analysis failed:', error);
            this.showErrorMessage('AI analysis failed. Please try again.');
        }
    }

    updateAIInsights(data) {
        document.getElementById('totalEvents').textContent = data.totalEvents;
        document.getElementById('anomaliesDetected').textContent = data.anomaliesDetected;
        document.getElementById('highRiskEvents').textContent = data.highRiskEvents;
        document.getElementById('aiConfidence').textContent = data.aiConfidence + '%';
    }

    displayAIExplanations(explanations) {
        const container = document.getElementById('explanationsList');
        container.innerHTML = '';

        explanations.forEach((exp, index) => {
            const div = document.createElement('div');
            div.className = 'ai-explanation';
            div.innerHTML = `
                <h4>🕐 ${exp.time} - ${exp.process} (Risk: ${exp.risk})</h4>
                <p>${exp.explanation}</p>
                <div>
                    ${exp.threats.map(threat => `<span class="threat-badge threat-${threat}">${threat.toUpperCase()}</span>`).join('')}
                </div>
            `;
            container.appendChild(div);
        });
    }

    updateThreatsTable(explanations) {
        const table = document.getElementById('threatsTable');
        const existingRows = table.querySelectorAll('tr');
        existingRows.forEach(row => row.remove());

        // Add header back
        const header = document.createElement('tr');
        header.innerHTML = `
            <th>Time</th>
            <th>Process</th>
            <th>Event</th>
            <th>AI Risk Score</th>
            <th>Threat Level</th>
            <th>AI Insights</th>
        `;
        table.appendChild(header);

        explanations.forEach(exp => {
            const row = document.createElement('tr');
            const threatClass = exp.risk >= 80 ? 'high' : exp.risk >= 60 ? 'medium' : 'low';
            row.className = `alert ${threatClass}`;
            
            row.innerHTML = `
                <td>${exp.time}</td>
                <td>${exp.process}</td>
                <td>AI-Detected</td>
                <td><div class="risk-bar ${threatClass}" style="width:${exp.risk}%">${exp.risk}</div></td>
                <td>${threatClass.toUpperCase()}</td>
                <td><button onclick="showDetails('${exp.time}')" class="ai-toggle">View AI Analysis</button></td>
            `;
            table.appendChild(row);
        });
    }

    async processQuery(query) {
        const queryLower = query.toLowerCase();
        
        // Simulate AI processing
        await new Promise(resolve => setTimeout(resolve, 500));

        if (!this.analysisData) {
            return "🤖 Please run AI analysis first to get security insights.";
        }

        if (queryLower.includes('total anomalies') || queryLower.includes('how many anomalies')) {
            return `📊 **Total Anomalies Detected**: ${this.analysisData.anomaliesDetected} out of ${this.analysisData.totalEvents} events`;
        }
        
        if (queryLower.includes('high risk')) {
            return `🔴 **High Risk Events**: ${this.analysisData.highRiskEvents} critical threats detected`;
        }
        
        if (queryLower.includes('confidence')) {
            return `🎯 **AI Confidence**: ${this.analysisData.aiConfidence}% accuracy in threat detection`;
        }
        
        if (queryLower.includes('threat patterns')) {
            const patterns = this.analysisData.threatPatterns.map(p => `• ${p}`).join('\n');
            return `🔍 **Top Threat Patterns**:\n${patterns}`;
        }
        
        if (queryLower.includes('help')) {
            return `🤖 **AI Assistant Commands**:\n• 'total anomalies' - Show anomaly count\n• 'high risk' - Show critical threats\n• 'confidence' - Show AI accuracy\n• 'threat patterns' - Show detected patterns\n• 'summary' - Get overall security summary`;
        }
        
        if (queryLower.includes('summary')) {
            return `📋 **Security Summary**:\n🔍 Total Events: ${this.analysisData.totalEvents}\n🚨 Anomalies: ${this.analysisData.anomaliesDetected}\n🔴 High Risk: ${this.analysisData.highRiskEvents}\n🟡 Medium Risk: ${this.analysisData.mediumRiskEvents}\n🟢 Low Risk: ${this.analysisData.lowRiskEvents}\n🎯 AI Confidence: ${this.analysisData.aiConfidence}%`;
        }
        
        return "🤖 I can help you analyze security data. Try asking about 'total anomalies', 'high risk events', 'threat patterns', or type 'help' for more options.";
    }

    showErrorMessage(message) {
        const chatMessages = document.getElementById('chatMessages');
        const errorDiv = document.createElement('div');
        errorDiv.className = 'ai-message';
        errorDiv.style.background = 'rgba(255, 0, 0, 0.2)';
        errorDiv.innerHTML = `❌ ${message}`;
        chatMessages.appendChild(errorDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
}

// Global AI Assistant instance
const aiAssistant = new AISecurityAssistant();

// Enhanced analysis function with AI
async function analyzeWithAI() {
    console.log('🚀 Starting AI-enhanced analysis...');
    
    // Show basic analysis first
    analyze();
    
    // Then run AI analysis
    const results = await aiAssistant.runAIAnalysis();
    
    if (results) {
        // Update summary with AI data
        document.getElementById('totalLogs').textContent = results.totalEvents;
        document.getElementById('anomalyCount').textContent = results.anomaliesDetected;
        
        // Show AI-enhanced summary
        document.getElementById('summaryBtn').style.display = 'block';
        document.getElementById('tableBtn').style.display = 'block';
    }
}

// Run local AI analysis (Python backend integration)
async function runLocalAI() {
    try {
        console.log('🧠 Running local AI analysis...');
        
        // In a real implementation, this would call the Python backend
        // For now, we'll simulate it
        const response = await fetch('/api/ai-analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                // File data would be sent here
            })
        });
        
        if (response.ok) {
            const results = await response.json();
            aiAssistant.analysisData = results;
            aiAssistant.updateAIInsights(results);
            document.getElementById('aiInsights').classList.remove('hidden');
        } else {
            throw new Error('Backend analysis failed');
        }
    } catch (error) {
        console.log('🔄 Fallback to simulated AI analysis...');
        // Fallback to client-side simulation
        analyzeWithAI();
    }
}

// Chat functionality
async function sendChatMessage() {
    const input = document.getElementById('chatInput');
    const query = input.value.trim();
    
    if (!query) return;
    
    const chatMessages = document.getElementById('chatMessages');
    
    // Add user message
    const userDiv = document.createElement('div');
    userDiv.className = 'ai-message';
    userDiv.style.background = 'rgba(0, 255, 136, 0.2)';
    userDiv.innerHTML = `👤 You: ${query}`;
    chatMessages.appendChild(userDiv);
    
    // Clear input
    input.value = '';
    
    // Get AI response
    const response = await aiAssistant.processQuery(query);
    
    // Add AI response
    const aiDiv = document.createElement('div');
    aiDiv.className = 'ai-message';
    aiDiv.innerHTML = `🤖 AI: ${response}`;
    chatMessages.appendChild(aiDiv);
    
    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function handleChatInput(event) {
    if (event.key === 'Enter') {
        sendChatMessage();
    }
}

function showAIExplanations() {
    const explanationsSection = document.getElementById('aiExplanations');
    explanationsSection.classList.toggle('hidden');
}

function showDetails(time) {
    if (aiAssistant.analysisData) {
        const explanation = aiAssistant.analysisData.explanations.find(exp => exp.time === time);
        if (explanation) {
            alert(`🤖 AI Analysis for ${explanation.process} at ${explanation.time}:\n\n${explanation.explanation}`);
        }
    }
}

// Enhanced show functions
function showSummary() {
    document.getElementById('summary').classList.toggle('hidden');
}

function showTable() {
    document.getElementById('tableSection').classList.toggle('hidden');
}

// File upload handler
document.getElementById('fileInput').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (file) {
        console.log(`📁 File selected: ${file.name}`);
        // File processing would happen here
    }
});
