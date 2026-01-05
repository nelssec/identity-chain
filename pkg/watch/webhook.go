package watch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type WebhookNotifier struct {
	url     string
	headers map[string]string
	client  *http.Client
}

func NewWebhookNotifier(url string, headers map[string]string) *WebhookNotifier {
	return &WebhookNotifier{
		url:     url,
		headers: headers,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type WebhookPayload struct {
	Timestamp time.Time       `json:"timestamp"`
	Event     string          `json:"event"`
	Findings  []FindingChange `json:"findings"`
	Summary   WebhookSummary  `json:"summary"`
}

type WebhookSummary struct {
	NewFindings   int `json:"new_findings"`
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
}

func (w *WebhookNotifier) Send(findings []FindingChange) {
	if len(findings) == 0 {
		return
	}

	summary := WebhookSummary{
		NewFindings: len(findings),
	}
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		}
	}

	payload := WebhookPayload{
		Timestamp: time.Now(),
		Event:     "new_findings",
		Findings:  findings,
		Summary:   summary,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to marshal webhook payload: %v\n", err)
		return
	}

	req, err := http.NewRequest("POST", w.url, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to create webhook request: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to send webhook: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "WARNING: Webhook returned status %d\n", resp.StatusCode)
	} else {
		fmt.Fprintf(os.Stderr, "Webhook sent: %d new findings (critical=%d, high=%d)\n",
			summary.NewFindings, summary.CriticalCount, summary.HighCount)
	}
}

type SlackPayload struct {
	Text        string            `json:"text"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

type SlackAttachment struct {
	Color  string `json:"color"`
	Title  string `json:"title"`
	Text   string `json:"text"`
	Footer string `json:"footer"`
}

func (w *WebhookNotifier) SendSlack(findings []FindingChange) {
	if len(findings) == 0 {
		return
	}

	criticalCount := 0
	highCount := 0
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		}
	}

	color := "warning"
	if criticalCount > 0 {
		color = "danger"
	}

	text := fmt.Sprintf("*Identity Chain Alert*: %d new security findings detected", len(findings))

	var attachmentText string
	for i, f := range findings {
		if i >= 5 {
			attachmentText += fmt.Sprintf("\n... and %d more", len(findings)-5)
			break
		}
		icon := ":warning:"
		if f.Severity == "critical" {
			icon = ":rotating_light:"
		}
		attachmentText += fmt.Sprintf("%s [%s] %s: %s (%s)\n", icon, f.Severity, f.CheckID, f.Name, f.Affected)
	}

	payload := SlackPayload{
		Text: text,
		Attachments: []SlackAttachment{
			{
				Color:  color,
				Title:  fmt.Sprintf("%d Critical, %d High", criticalCount, highCount),
				Text:   attachmentText,
				Footer: "Identity Chain Watcher",
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to marshal slack payload: %v\n", err)
		return
	}

	req, err := http.NewRequest("POST", w.url, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to create slack request: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to send slack webhook: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "WARNING: Slack webhook returned status %d\n", resp.StatusCode)
	}
}
