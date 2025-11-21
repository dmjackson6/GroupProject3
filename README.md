# Project Tutwiler Dashboard

## Quick Start

### Option 1: Open Directly (Development Testing)
Simply open `client/index.html` in your browser to test the frontend (API calls will need the backend running).

### Option 2: Serve via Backend (Recommended)
The backend is configured to serve this client folder automatically:

```Open terminal
cd api\backend\ProjectTutwiler
dotnet run
```

Then navigate to: **`http://localhost:5239`**

---

## Features

### Retro-Futuristic Cyberpunk Design
- **Aquatic Blue Theme** (#00D9FF primary, #00FFF0 accent)
- **Scanline CRT Effect** - Subtle overlay for retro terminal feel
- **Neon Glow Effects** - Blue text shadows and borders
- **Color-Coded Priorities:**
  - 🔴 **Critical** - Red (#FF0844)
  - 🟠 **High** - Orange (#FF8C00)
  - 🟡 **Medium** - Yellow (#FFD700)
  - 🟢 **Low** - Green (#00FF88)

### Dashboard Components
1. **Metrics Cards** - Real-time vulnerability counts by priority
2. **Stats Row** - Total count, exploited count, last ingestion time
3. **Filters** - Priority level, time range, search box
4. **Vulnerability List** - Scrollable cards with color-coded borders
5. **Detail Panel** - Sticky sidebar showing full vulnerability analysis
6. **Pagination** - Navigate through large datasets

---

## Configuration

### API Endpoint
Update the API base URL in `resources/scripts/main.js`:

```javascript
class DashboardApp {
    constructor() {
        this.API_BASE = 'http://localhost:5239/api'; // ← Change port here
        // ...
    }
}
```

### Page Size
Adjust items per page in `resources/scripts/main.js`:

```javascript
this.pageSize = 20; // ← Change from 20 to desired value
```

### Colors
Modify CSS variables in `resources/styles/main.css`:

```css
:root {
    --primary-cyan: #00D9FF;
    --accent-cyan: #00FFF0;
    --dark-bg: #0A0E27;
    /* ... */
}
```

---

## How to Use

### 1. View Statistics
- Check metric cards at top for priority breakdown
- Monitor total vulnerabilities and exploited count

### 2. Filter Vulnerabilities
- **Priority Filter**: Select CRITICAL/HIGH/MEDIUM/LOW
- **Time Range**: Last 24h/7d/30d/90d or all time
- **Search**: Type CVE ID or keywords (auto-searches after 500ms)

### 3. View Details
- Click any vulnerability card in the list
- Card highlights with cyan border
- Detail panel populates on right side
- View bio-impact scores with animated progress bars
- Read action recommendations

### 4. Navigate
- Use **PREVIOUS/NEXT** buttons to paginate
- Clear search to return to full list
- Click **REFRESH** to reload data

---

## Browser Support

✅ Chrome (recommended)  
✅ Firefox  
✅ Edge  
✅ Safari  

---

## Responsive Design

- **Desktop (>1200px)**: Full 2-column layout
- **Tablet (768-1200px)**: Narrower detail panel
- **Mobile (<768px)**: Single column, detail panel below list

---

## Troubleshooting

### Dashboard Not Loading
1. Verify backend is running: `dotnet run` in `api/backend/ProjectTutwiler`
2. Check browser console (F12) for errors
3. Confirm API port matches in `main.js`

### No Data Showing
1. Run ingestion job via API or Hangfire dashboard
2. Trigger processing job to analyze vulnerabilities
3. Check filters aren't too restrictive

### Styling Issues
1. Hard refresh: **Ctrl+F5**
2. Clear browser cache
3. Verify CSS file loads (Network tab)

### API Connection Errors
1. Check CORS is enabled in backend `Program.cs`
2. Verify API is running on correct port
3. Test API directly: `http://localhost:5239/swagger`

---

## Key Interactions

### Search Functionality
- Debounced with 500ms delay
- Searches CVE IDs, descriptions, and vendor names
- Results limited to 50 items
- Pagination hidden during search

### Filtering
- Priority filter applies immediately
- Time range filters by published date
- Filters can be combined
- Reset by clearing all dropdowns

### Detail Panel
- Sticky positioning (follows scroll)
- Shows full vulnerability info
- Displays AI bio-impact analysis
- Lists safe action recommendations
- Includes score breakdowns with visual bars

---

## Production Notes

When deploying to production:

1. **Update CORS Policy** in `Program.cs`:
```csharp
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(corsBuilder =>
    {
        corsBuilder.WithOrigins("https://yourdomain.com")
               .AllowAnyMethod()
               .AllowAnyHeader();
    });
});
```

2. **Update API Base URL** in `main.js`:
```javascript
this.API_BASE = 'https://api.yourdomain.com/api';
```

3. **Enable HTTPS** and update footer links in `index.html`

---

## Technical Details

- **Framework**: Vanilla JavaScript (no dependencies)
- **Styling**: Pure CSS3 with CSS Grid and Flexbox
- **API Calls**: Fetch API with async/await
- **State Management**: Class-based architecture
- **Event Handling**: Debounced inputs, delegated click events
- **Performance**: Efficient DOM updates, hardware acceleration

**Project Tutwiler** | Cyberbiosecurity Research Initiative

