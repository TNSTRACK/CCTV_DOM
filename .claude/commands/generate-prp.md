# Generate PRP Command - DOM CCTV

You are an expert technical architect specializing in CCTV systems, video surveillance, and enterprise web applications. You will analyze the provided INITIAL.md file and generate a comprehensive Product Requirements Prompt (PRP) specifically tailored for the DOM CCTV system.

## Your Task

Read and analyze the INITIAL.md file provided in `$ARGUMENTS`. Create a detailed PRP that includes all necessary context for implementing the requested feature in the DOM CCTV system.

## Research Phase

Before creating the PRP, research the following:

1. **Analyze Project Context:**
   - Read `CLAUDE.md` for project-specific rules and architecture
   - Review existing documentation in `docs/` folder
   - Examine relevant examples in `examples/` folder
   - Understand the technology stack and patterns

2. **Hikvision Integration Analysis:**
   - Identify which Hikvision APIs (HikCentral OpenAPI or ISAPI) are needed
   - Determine video streaming requirements (RTSP, HTTP, etc.)
   - Consider ANPR integration patterns if applicable
   - Plan for error handling and network resilience

3. **Database Impact Assessment:**
   - Review current schema in `docs/database_schema_dom_cctv.md`
   - Identify required table changes or new tables
   - Plan for data migrations if needed
   - Consider performance implications and indexing

4. **Frontend Architecture Review:**
   - Understand React component patterns from `docs/frontend_dom_cctv.md`
   - Identify Material-UI components to use
   - Plan state management approach (TanStack Query + Zustand)
   - Consider responsive design requirements

5. **Backend Service Design:**
   - Review Node.js/Express patterns from `docs/backend_dom_cctv.md`
   - Plan new routes, controllers, services
   - Consider authentication and authorization
   - Plan API design following project conventions

## PRP Structure

Create the PRP with the following sections:

### 1. Executive Summary
- Brief description of the feature
- Business value and user impact
- Technical complexity assessment (1-10 scale)
- Estimated development time

### 2. Context & Background
- Why this feature is needed
- How it fits into the overall DOM CCTV system
- Dependencies on other features
- User roles that will benefit

### 3. Technical Requirements

#### Database Changes
- New tables, fields, or indexes required
- Migration scripts needed
- Performance considerations
- Backup/rollback strategy

#### Backend Implementation
- New API endpoints required
- Service layer changes
- Middleware requirements
- Hikvision API integration points

#### Frontend Implementation
- New components to create
- Pages to modify or create
- State management approach
- User interface requirements

#### Hikvision Integration
- Specific APIs to use
- Authentication requirements
- Error handling strategies
- Performance optimization

### 4. Implementation Plan

#### Phase 1: Foundation (Database + Backend Core)
- Database changes and migrations
- Core backend services
- Basic API endpoints
- Unit tests for core functionality

#### Phase 2: Hikvision Integration
- API integration implementation
- Error handling and retry logic
- Integration tests
- Performance optimization

#### Phase 3: Frontend Implementation
- Component development
- Page integration
- State management setup
- User interface polish

#### Phase 4: Testing & Optimization
- End-to-end testing
- Performance testing
- User acceptance testing
- Documentation updates

### 5. Acceptance Criteria
- Functional requirements checklist
- Performance benchmarks
- Security requirements
- User experience goals

### 6. Risk Assessment
- Technical risks and mitigation strategies
- Integration challenges
- Performance concerns
- Security considerations

### 7. Testing Strategy
- Unit testing approach
- Integration testing requirements
- End-to-end testing scenarios
- Performance testing plan

### 8. Validation Steps
Each phase must include validation steps that ensure:
- Code passes all tests (>80% coverage)
- Integration with Hikvision APIs works correctly
- Performance requirements are met
- Security standards are maintained
- User interface is responsive and accessible

## Implementation Commands

Provide specific commands for implementation:

```bash
# Database migrations
npx prisma generate
npx prisma db push

# Backend development
npm run dev:backend
npm run test:backend

# Frontend development  
npm run dev:frontend
npm run test:frontend

# Integration testing
npm run test:integration

# Build and deployment
npm run build
npm run start:production
```

## Quality Assurance

Rate your confidence in this PRP from 1-10 and explain:
- How well the requirements are understood
- Completeness of technical specifications
- Feasibility of implementation plan
- Clarity of acceptance criteria

If confidence is below 8, identify what additional information is needed.

## Files to Create

List all files that will need to be created or modified:

### Backend Files:
- Routes: `/src/routes/*.routes.ts`
- Controllers: `/src/controllers/*.controller.ts`
- Services: `/src/services/*.service.ts`
- Models: `/prisma/schema.prisma`
- Migrations: `/prisma/migrations/`

### Frontend Files:
- Components: `/src/components/**/*.tsx`
- Pages: `/src/pages/**/*.tsx`
- Hooks: `/src/hooks/*.ts`
- Services: `/src/services/*.ts`

### Test Files:
- Backend tests: `/src/__tests__/**/*.test.ts`
- Frontend tests: `/src/components/**/*.test.tsx`
- Integration tests: `/tests/integration/*.test.ts`

### Documentation:
- API documentation updates
- User documentation updates
- Technical documentation updates

Generate a comprehensive PRP that serves as a complete blueprint for implementing the requested feature in the DOM CCTV system.